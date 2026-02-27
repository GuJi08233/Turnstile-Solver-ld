"""
认证模块：Linux DO Connect OAuth2 + 管理员本地认证
"""
import os
import hashlib
import hmac
import secrets
import logging
import functools
from urllib.parse import urlencode

import httpx
from quart import session, redirect, request, jsonify

logger = logging.getLogger("TurnstileAPIServer")

# HTTP 客户端单例
_http_client = None

async def _get_http_client() -> httpx.AsyncClient:
    """获取共享 HTTP 客户端"""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=15)
    return _http_client

async def close_http_client() -> None:
    """关闭共享 HTTP 客户端"""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None

# Linux DO Connect OAuth2 端点
AUTHORIZE_URL = "https://connect.linux.do/oauth2/authorize"
TOKEN_URL = "https://connect.linux.do/oauth2/token"
USER_INFO_URL = "https://connect.linux.do/api/user"


def get_oauth_config() -> dict:
    """从环境变量读取 OAuth 配置"""
    return {
        "client_id": os.environ.get("LINUXDO_CLIENT_ID", ""),
        "client_secret": os.environ.get("LINUXDO_CLIENT_SECRET", ""),
        "redirect_uri": os.environ.get("LINUXDO_REDIRECT_URI", ""),
    }


def get_admin_credentials() -> tuple:
    """从环境变量读取管理员凭据"""
    return (
        os.environ.get("ADMIN_USERNAME", "admin"),
        os.environ.get("ADMIN_PASSWORD", ""),
    )


def oauth_configured() -> bool:
    """检查 OAuth 是否已配置"""
    cfg = get_oauth_config()
    return bool(cfg["client_id"] and cfg["client_secret"] and cfg["redirect_uri"])


def build_authorize_url(state: str) -> str:
    """构建 OAuth2 授权 URL"""
    cfg = get_oauth_config()
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": "user",
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}"


async def exchange_code_for_token(code: str) -> dict | None:
    """用授权码换取 access_token"""
    cfg = get_oauth_config()
    data = {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code": code,
        "redirect_uri": cfg["redirect_uri"],
        "grant_type": "authorization_code",
    }
    try:
        client = await _get_http_client()
        resp = await client.post(
            TOKEN_URL,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        return None


async def fetch_user_info(access_token: str) -> dict | None:
    """使用 access_token 获取用户信息"""
    try:
        client = await _get_http_client()
        resp = await client.get(
            USER_INFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"OAuth fetch user info failed: {e}")
        return None


def verify_admin(username: str, password: str) -> bool:
    """验证管理员凭据"""
    expected_user, expected_pass = get_admin_credentials()
    if not expected_pass:
        return False
    return hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_pass)


def require_admin(f):
    """管理员认证装饰器"""
    @functools.wraps(f)
    async def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            if request.is_json or request.path.startswith("/admin/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/admin/login")
        return await f(*args, **kwargs)
    return decorated


def require_user(f):
    """用户认证装饰器"""
    @functools.wraps(f)
    async def decorated(*args, **kwargs):
        if not session.get("user_id"):
            if request.is_json:
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/auth/login")
        return await f(*args, **kwargs)
    return decorated


def generate_state() -> str:
    """生成 OAuth state 参数防 CSRF"""
    return secrets.token_urlsafe(32)
