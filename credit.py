"""
EasyPay 积分充值集成模块
"""
import os
import time
import hashlib
import hmac
import secrets
from urllib.parse import urlencode


def get_credit_config() -> dict:
    """从环境变量读取 EasyPay 配置"""
    return {
        "pid": os.environ.get("CREDIT_PID", ""),
        "key": os.environ.get("CREDIT_KEY", ""),
    }


def credit_configured() -> bool:
    """检查是否配置了 PID/KEY"""
    cfg = get_credit_config()
    return bool(cfg["pid"] and cfg["key"])


def epay_sign(params: dict, key: str) -> str:
    """
    EasyPay 签名算法：
    1. 过滤 sign、sign_type 和空值
    2. 按 key ASCII 升序排序
    3. 拼成 k1=v1&k2=v2
    4. 末尾直接拼 key（无 & 分隔）
    5. MD5 取小写 hex
    """
    filtered = {
        k: v for k, v in params.items()
        if k not in ("sign", "sign_type") and v is not None and str(v) != ""
    }
    sorted_keys = sorted(filtered.keys())
    query = "&".join(f"{k}={filtered[k]}" for k in sorted_keys)
    sign_str = query + key
    return hashlib.md5(sign_str.encode("utf-8")).hexdigest()


def verify_sign(params: dict, key: str) -> bool:
    """验签（hmac.compare_digest 防时序攻击）"""
    sign = params.get("sign", "")
    if not sign:
        return False
    expected = epay_sign(params, key)
    return hmac.compare_digest(sign, expected)


def generate_out_trade_no(user_id: int) -> str:
    """生成唯一订单号 TS{uid}_{timestamp}_{hex}"""
    ts = int(time.time())
    rand = secrets.token_hex(4)
    return f"TS{user_id}_{ts}_{rand}"


def build_payment_url(pid: str, key: str, out_trade_no: str, name: str,
                      money: str, notify_url: str, return_url: str,
                      sitename: str = "Turnstile Solver") -> str:
    """构建支付跳转 URL"""
    params = {
        "pid": pid,
        "type": "alipay",
        "out_trade_no": out_trade_no,
        "notify_url": notify_url,
        "return_url": return_url,
        "name": name,
        "money": money,
        "sitename": sitename,
    }
    params["sign"] = epay_sign(params, key)
    params["sign_type"] = "MD5"
    # Linux DO Credit EasyPay 网关
    gateway = os.environ.get("CREDIT_GATEWAY", "https://shop.linux.do/pay/")
    return f"{gateway}submit.php?{urlencode(params)}"
