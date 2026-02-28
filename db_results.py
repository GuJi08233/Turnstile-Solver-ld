import asyncio
import aiosqlite
import hashlib
import json
import logging
import os
import secrets
from typing import Dict, Any, Optional, Union, List

DB_PATH = os.environ.get("DB_PATH", "results.db")

# 积分系统常量
CREDIT_COST_PER_TASK = 1
TRUST_LEVEL_INITIAL_CREDITS = {0: 0, 1: 10, 2: 50, 3: 100, 4: 200}
TRUST_LEVEL_CHECKIN_CREDITS = {0: 1, 1: 2, 2: 5, 3: 10, 4: 20}
CREDIT_EXCHANGE_RATE = 1.0  # 1 元 = 1 积分

# 数据库优化 PRAGMA 设置
PRAGMA_SETTINGS = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA cache_size=10000",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA busy_timeout=30000"
]

# 全局连接管理器
_db_connection = None
_db_lock = asyncio.Lock()

async def get_db():
    """获取全局数据库连接（单例）"""
    global _db_connection
    if _db_connection is None:
        async with _db_lock:
            if _db_connection is None:
                _db_connection = await aiosqlite.connect(DB_PATH)
                _db_connection.row_factory = aiosqlite.Row
                for pragma in PRAGMA_SETTINGS:
                    await _db_connection.execute(pragma)
    return _db_connection

async def close_db():
    """关闭全局数据库连接"""
    global _db_connection
    if _db_connection is not None:
        await _db_connection.close()
        _db_connection = None

async def init_db():
    """以 WAL 模式初始化数据库结果表"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            for pragma in PRAGMA_SETTINGS:
                await db.execute(pragma)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    task_id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # 迁移：为旧表添加 status 列
            try:
                await db.execute("ALTER TABLE results ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
            except Exception:
                pass  # 列已存在
            # status + created_at 索引
            await db.execute("CREATE INDEX IF NOT EXISTS idx_results_status ON results(status)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_results_created_at ON results(created_at DESC)")
            # 迁移已有数据的 status
            await db.execute("UPDATE results SET status = 'failed' WHERE status = 'pending' AND data LIKE '%CAPTCHA_FAIL%'")
            await db.execute("UPDATE results SET status = 'success' WHERE status = 'pending' AND data NOT LIKE '%CAPTCHA_NOT_READY%' AND data NOT LIKE '%CAPTCHA_FAIL%' AND data LIKE '%value%'")

            await db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    linuxdo_id INTEGER UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    name TEXT,
                    avatar_template TEXT,
                    trust_level INTEGER DEFAULT 0,
                    active INTEGER DEFAULT 1,
                    silenced INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS credits (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id),
                    balance REAL NOT NULL DEFAULT 0,
                    total_earned REAL NOT NULL DEFAULT 0,
                    total_spent REAL NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS credit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    balance_after REAL NOT NULL,
                    type TEXT NOT NULL,
                    description TEXT,
                    related_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_credit_log_user ON credit_log(user_id, created_at DESC)")
            await db.execute("""
                CREATE TABLE IF NOT EXISTS checkin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    checkin_date DATE NOT NULL,
                    credits_earned REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, checkin_date)
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    out_trade_no TEXT UNIQUE NOT NULL,
                    trade_no TEXT,
                    amount REAL NOT NULL,
                    money REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    paid_at TIMESTAMP,
                    raw_notify TEXT
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC)")

            await db.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    key_hash TEXT UNIQUE NOT NULL,
                    key_prefix TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used TIMESTAMP,
                    revoked INTEGER DEFAULT 0
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")

            await db.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT NOT NULL DEFAULT 'http',
                    address TEXT NOT NULL,
                    username TEXT DEFAULT '',
                    password TEXT DEFAULT '',
                    enabled INTEGER DEFAULT 1,
                    last_used TIMESTAMP,
                    fail_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await db.execute("CREATE INDEX IF NOT EXISTS idx_proxies_enabled ON proxies(enabled)")

            await db.commit()
            logging.getLogger("TurnstileAPIServer").info(f"Database initialized in WAL mode: {DB_PATH}")
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Database initialization error: {e}")
        raise

async def save_result(task_id: str, task_type: str, data: Union[Dict[str, Any], str]) -> None:
    """保存结果到数据库"""
    try:
        db = await get_db()
        data_json = json.dumps(data) if isinstance(data, dict) else data
        # 自动推断 status
        if isinstance(data, dict):
            if data.get("status") == "CAPTCHA_NOT_READY":
                status = "pending"
            elif data.get("value") == "CAPTCHA_FAIL":
                status = "failed"
            elif data.get("value"):
                status = "success"
            else:
                status = "pending"
        else:
            status = "pending"

        await db.execute(
            "REPLACE INTO results (task_id, type, data, status) VALUES (?, ?, ?, ?)",
            (task_id, task_type, data_json, status)
        )
        await db.commit()
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error saving result {task_id}: {e}")
        raise

async def load_result(task_id: str) -> Optional[Union[Dict[str, Any], str]]:
    """从数据库加载结果"""
    try:
        db = await get_db()
        async with db.execute("SELECT data FROM results WHERE task_id = ?", (task_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                try:
                    return json.loads(row[0])
                except json.JSONDecodeError:
                    return row[0]
        return None
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error loading result {task_id}: {e}")
        return None

async def load_all_results() -> Dict[str, Any]:
    """从数据库加载所有结果"""
    try:
        db = await get_db()
        results = {}
        async with db.execute("SELECT task_id, data FROM results") as cursor:
            async for row in cursor:
                try:
                    results[row[0]] = json.loads(row[1])
                except json.JSONDecodeError:
                    results[row[0]] = row[1]
        return results
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error loading all results: {e}")
        return {}

async def delete_result(task_id: str) -> None:
    """从数据库删除结果"""
    try:
        db = await get_db()
        await db.execute("DELETE FROM results WHERE task_id = ?", (task_id,))
        await db.commit()
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error deleting result {task_id}: {e}")

async def get_pending_count() -> int:
    """获取待处理任务数量"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM results WHERE status = 'pending'") as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting pending count: {e}")
        return 0

async def load_recent_results(page: int = 1, per_page: int = 20, status_filter: str = "all") -> Dict[str, Any]:
    """分页查询任务列表，按时间倒序，支持 status 过滤"""
    try:
        db = await get_db()

        # 构建 WHERE 子句
        where = ""
        params: list = []
        if status_filter and status_filter != "all":
            where = " WHERE status = ?"
            params.append(status_filter)

        # 总数
        async with db.execute(f"SELECT COUNT(*) FROM results{where}", params) as cursor:
            total = (await cursor.fetchone())[0]

        offset = (page - 1) * per_page
        rows = []
        async with db.execute(
            f"SELECT task_id, type, data, created_at FROM results{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ) as cursor:
            async for row in cursor:
                try:
                    data = json.loads(row[2])
                except json.JSONDecodeError:
                    data = row[2]
                rows.append({
                    "task_id": row[0],
                    "type": row[1],
                    "data": data,
                    "created_at": row[3]
                })

        return {
            "items": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error loading recent results: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


async def get_task_stats() -> Dict[str, int]:
    """返回 {total, pending, success, failed} 统计（单条查询）"""
    try:
        db = await get_db()
        async with db.execute(
            "SELECT COUNT(*), SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) FROM results"
        ) as cursor:
            row = await cursor.fetchone()
            total = row[0] or 0
            pending = row[1] or 0
            failed = row[2] or 0
            success = total - pending - failed
        return {"total": total, "pending": pending, "success": success, "failed": failed}
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting task stats: {e}")
        return {"total": 0, "pending": 0, "success": 0, "failed": 0}


async def cleanup_old_results(days_old: int = 1) -> int:
    """清理超过指定天数的旧结果"""
    try:
        try:
            days_old = int(days_old)
        except (TypeError, ValueError):
            days_old = 1
        days_old = max(1, min(days_old, 3650))
        db = await get_db()
        cursor = await db.execute(
            "DELETE FROM results WHERE created_at < datetime('now', ?)",
            (f"-{days_old} days",),
        )
        deleted_count = cursor.rowcount
        if deleted_count is None or deleted_count < 0:
            deleted_count = 0
        await db.commit()
        logging.getLogger("TurnstileAPIServer").info(f"Cleaned up {deleted_count} old results")
        return deleted_count
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error cleaning up old results: {e}")
        return 0


# ========== 用户相关函数 ==========

async def upsert_user(user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """插入或更新用户信息，返回用户记录"""
    try:
        db = await get_db()
        await db.execute("""
            INSERT INTO users (linuxdo_id, username, name, avatar_template, trust_level, active, silenced, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(linuxdo_id) DO UPDATE SET
                username=excluded.username,
                name=excluded.name,
                avatar_template=excluded.avatar_template,
                trust_level=excluded.trust_level,
                active=excluded.active,
                silenced=excluded.silenced,
                last_login=CURRENT_TIMESTAMP
        """, (
            user_info.get("id"),
            user_info.get("username", ""),
            user_info.get("name", ""),
            user_info.get("avatar_template", ""),
            user_info.get("trust_level", 0),
            1 if user_info.get("active", True) else 0,
            1 if user_info.get("silenced", False) else 0,
        ))
        await db.commit()
        return await get_user_by_linuxdo_id(user_info["id"])
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error upserting user: {e}")
        return None


async def get_user_by_linuxdo_id(linuxdo_id: int) -> Optional[Dict[str, Any]]:
    """根据 Linux DO ID 获取用户"""
    try:
        db = await get_db()
        async with db.execute("SELECT * FROM users WHERE linuxdo_id = ?", (linuxdo_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
        return None
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting user {linuxdo_id}: {e}")
        return None


async def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """根据内部 ID 获取用户"""
    try:
        db = await get_db()
        async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
        return None
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting user by id {user_id}: {e}")
        return None


async def get_all_users(page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """分页获取所有用户"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM users") as cursor:
            total = (await cursor.fetchone())[0]

        offset = (page - 1) * per_page
        rows = []
        async with db.execute(
            "SELECT * FROM users ORDER BY last_login DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ) as cursor:
            async for row in cursor:
                rows.append(dict(row))

        return {
            "items": rows,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting all users: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


# ========== 积分系统函数 ==========

async def init_user_credits(user_id: int, trust_level: int) -> None:
    """首次登录初始化用户积分"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "INSERT OR IGNORE INTO credits (user_id, balance, total_earned) VALUES (?, ?, ?)",
            (user_id, TRUST_LEVEL_INITIAL_CREDITS.get(trust_level, 0), TRUST_LEVEL_INITIAL_CREDITS.get(trust_level, 0))
        )
        if cursor.rowcount > 0:
            initial = TRUST_LEVEL_INITIAL_CREDITS.get(trust_level, 0)
            if initial > 0:
                await db.execute(
                    "INSERT INTO credit_log (user_id, amount, balance_after, type, description) VALUES (?, ?, ?, 'initial', ?)",
                    (user_id, initial, initial, f"注册赠送积分 (TL{trust_level})")
                )
        await db.commit()
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error init user credits: {e}")


async def get_user_credits(user_id: int) -> Dict[str, Any]:
    """获取用户积分信息"""
    try:
        db = await get_db()
        async with db.execute("SELECT * FROM credits WHERE user_id = ?", (user_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
        return {"user_id": user_id, "balance": 0, "total_earned": 0, "total_spent": 0}
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error get user credits: {e}")
        return {"user_id": user_id, "balance": 0, "total_earned": 0, "total_spent": 0}


async def deduct_credits(user_id: int, amount: float, description: str = "", related_id: str = "") -> bool:
    """原子扣减积分，余额不足返回 False"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "UPDATE credits SET balance = balance - ?, total_spent = total_spent + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND balance >= ?",
            (amount, amount, user_id, amount)
        )
        if cursor.rowcount == 0:
            return False
        async with db.execute("SELECT balance FROM credits WHERE user_id = ?", (user_id,)) as c:
            row = await c.fetchone()
            balance_after = row[0] if row else 0
        await db.execute(
            "INSERT INTO credit_log (user_id, amount, balance_after, type, description, related_id) VALUES (?, ?, ?, 'consume', ?, ?)",
            (user_id, -amount, balance_after, description, related_id)
        )
        await db.commit()
        return True
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error deduct credits: {e}")
        return False


async def refund_credits(user_id: int, amount: float, description: str = "", related_id: str = "") -> bool:
    """退还积分"""
    try:
        db = await get_db()
        await db.execute(
            "UPDATE credits SET balance = balance + ?, total_spent = total_spent - ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
            (amount, amount, user_id)
        )
        async with db.execute("SELECT balance FROM credits WHERE user_id = ?", (user_id,)) as c:
            row = await c.fetchone()
            balance_after = row[0] if row else 0
        await db.execute(
            "INSERT INTO credit_log (user_id, amount, balance_after, type, description, related_id) VALUES (?, ?, ?, 'refund', ?, ?)",
            (user_id, amount, balance_after, description, related_id)
        )
        await db.commit()
        return True
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error refund credits: {e}")
        return False


async def add_credits(user_id: int, amount: float, credit_type: str, description: str = "", related_id: str = "") -> bool:
    """通用积分增加"""
    try:
        db = await get_db()
        await db.execute(
            "INSERT INTO credits (user_id, balance, total_earned) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET balance = balance + ?, total_earned = total_earned + ?, updated_at = CURRENT_TIMESTAMP",
            (user_id, amount, amount, amount, amount)
        )
        async with db.execute("SELECT balance FROM credits WHERE user_id = ?", (user_id,)) as c:
            row = await c.fetchone()
            balance_after = row[0] if row else 0
        await db.execute(
            "INSERT INTO credit_log (user_id, amount, balance_after, type, description, related_id) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, amount, balance_after, credit_type, description, related_id)
        )
        await db.commit()
        return True
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error add credits: {e}")
        return False


async def get_credit_log(user_id: int, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """用户积分流水分页"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM credit_log WHERE user_id = ?", (user_id,)) as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute(
            "SELECT * FROM credit_log WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, per_page, offset)
        ) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error get credit log: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


# ========== 签到函数 ==========

async def daily_checkin(user_id: int, trust_level: int) -> Optional[Dict[str, Any]]:
    """每日签到，返回 {credits_earned, new_balance} 或 None（已签到）"""
    try:
        db = await get_db()
        credits_earned = TRUST_LEVEL_CHECKIN_CREDITS.get(trust_level, 1)
        try:
            await db.execute(
                "INSERT INTO checkin (user_id, checkin_date, credits_earned) VALUES (?, DATE('now'), ?)",
                (user_id, credits_earned)
            )
        except aiosqlite.IntegrityError:
            return None  # 已签到
        await db.execute(
            "INSERT INTO credits (user_id, balance, total_earned) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET balance = balance + ?, total_earned = total_earned + ?, updated_at = CURRENT_TIMESTAMP",
            (user_id, credits_earned, credits_earned, credits_earned, credits_earned)
        )
        async with db.execute("SELECT balance FROM credits WHERE user_id = ?", (user_id,)) as c:
            row = await c.fetchone()
            new_balance = row[0] if row else 0
        await db.execute(
            "INSERT INTO credit_log (user_id, amount, balance_after, type, description) VALUES (?, ?, ?, 'checkin', '每日签到')",
            (user_id, credits_earned, new_balance)
        )
        await db.commit()
        return {"credits_earned": credits_earned, "new_balance": new_balance}
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error daily checkin: {e}")
        return None


async def get_checkin_status(user_id: int) -> Dict[str, Any]:
    """获取签到状态：今日是否签到、连续天数"""
    try:
        db = await get_db()
        async with db.execute(
            "SELECT COUNT(*) FROM checkin WHERE user_id = ? AND checkin_date = DATE('now')", (user_id,)
        ) as cursor:
            checked_today = (await cursor.fetchone())[0] > 0
        async with db.execute(
            "SELECT checkin_date FROM checkin WHERE user_id = ? ORDER BY checkin_date DESC LIMIT 30", (user_id,)
        ) as cursor:
            dates = [row[0] for row in await cursor.fetchall()]
        streak = 0
        if dates:
            from datetime import date, timedelta
            today = date.today()
            for i, d in enumerate(dates):
                expected = (today - timedelta(days=i)).isoformat()
                if d == expected:
                    streak += 1
                else:
                    break
        return {"checked_today": checked_today, "streak": streak}
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error get checkin status: {e}")
        return {"checked_today": False, "streak": 0}


# ========== 订单函数 ==========

async def create_order(user_id: int, out_trade_no: str, money: float, amount: float) -> Optional[int]:
    """创建待支付订单，返回订单 ID"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "INSERT INTO orders (user_id, out_trade_no, amount, money) VALUES (?, ?, ?, ?)",
            (user_id, out_trade_no, amount, money)
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error create order: {e}")
        return None


async def get_order_by_trade_no(out_trade_no: str) -> Optional[Dict[str, Any]]:
    """根据商户订单号查询订单"""
    try:
        db = await get_db()
        async with db.execute("SELECT * FROM orders WHERE out_trade_no = ?", (out_trade_no,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error get order: {e}")
        return None


async def update_order_paid(out_trade_no: str, trade_no: str, raw_notify: str) -> bool:
    """标记订单已支付（防重复）"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "UPDATE orders SET status = 'paid', trade_no = ?, paid_at = CURRENT_TIMESTAMP, raw_notify = ? WHERE out_trade_no = ? AND status = 'pending'",
            (trade_no, raw_notify, out_trade_no)
        )
        await db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error update order paid: {e}")
        return False


async def get_user_orders(user_id: int, page: int = 1, per_page: int = 20) -> Dict[str, Any]:
    """用户订单分页"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM orders WHERE user_id = ?", (user_id,)) as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute(
            "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (user_id, per_page, offset)
        ) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error get user orders: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


# ========== 管理员积分函数 ==========

async def admin_get_all_credits(page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """管理员查看所有用户积分（JOIN users）"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM credits") as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute("""
            SELECT u.id, u.username, u.name, u.trust_level, c.balance, c.total_earned, c.total_spent, c.updated_at
            FROM credits c JOIN users u ON c.user_id = u.id
            ORDER BY c.balance DESC LIMIT ? OFFSET ?
        """, (per_page, offset)) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error admin get all credits: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


async def admin_adjust_credits(user_id: int, amount: float, description: str = "") -> bool:
    """管理员调整积分"""
    try:
        db = await get_db()
        if amount >= 0:
            await db.execute(
                "INSERT INTO credits (user_id, balance, total_earned) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET balance = balance + ?, total_earned = total_earned + ?, updated_at = CURRENT_TIMESTAMP",
                (user_id, amount, amount, amount, amount)
            )
        else:
            await db.execute(
                "UPDATE credits SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                (amount, user_id)
            )
        async with db.execute("SELECT balance FROM credits WHERE user_id = ?", (user_id,)) as c:
            row = await c.fetchone()
            balance_after = row[0] if row else 0
        await db.execute(
            "INSERT INTO credit_log (user_id, amount, balance_after, type, description) VALUES (?, ?, ?, 'admin_adjust', ?)",
            (user_id, amount, balance_after, description or "管理员调整")
        )
        await db.commit()
        return True
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error admin adjust credits: {e}")
        return False


async def admin_get_all_orders(page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """管理员查看所有订单"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM orders") as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute("""
            SELECT o.*, u.username FROM orders o LEFT JOIN users u ON o.user_id = u.id
            ORDER BY o.created_at DESC LIMIT ? OFFSET ?
        """, (per_page, offset)) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error admin get all orders: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


# ========== API Key 函数 ==========

MAX_KEYS_PER_USER = 5


async def create_api_key(user_id: int, name: str = "") -> Optional[str]:
    """生成 API Key，存储哈希，返回明文（仅此一次可见）。超过限制返回 None。"""
    try:
        db = await get_db()
        async with db.execute(
            "SELECT COUNT(*) FROM api_keys WHERE user_id = ? AND revoked = 0", (user_id,)
        ) as cursor:
            count = (await cursor.fetchone())[0]
        if count >= MAX_KEYS_PER_USER:
            return None

        raw_key = "ts_" + secrets.token_hex(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:8]

        await db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?)",
            (user_id, key_hash, key_prefix, name)
        )
        await db.commit()
        return raw_key
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error creating API key: {e}")
        return None


async def validate_api_key(raw_key: str) -> Optional[int]:
    """验证 API Key，返回 user_id 或 None。顺带更新 last_used。"""
    try:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db = await get_db()
        async with db.execute(
            "SELECT id, user_id FROM api_keys WHERE key_hash = ? AND revoked = 0",
            (key_hash,)
        ) as cursor:
            row = await cursor.fetchone()
        if not row:
            return None
        key_id, user_id = row[0], row[1]
        await db.execute(
            "UPDATE api_keys SET last_used = CURRENT_TIMESTAMP WHERE id = ?", (key_id,)
        )
        await db.commit()
        return user_id
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error validating API key: {e}")
        return None


async def list_api_keys(user_id: int) -> List[Dict[str, Any]]:
    """列出用户的 API Key（不含哈希）"""
    try:
        db = await get_db()
        rows = []
        async with db.execute(
            "SELECT id, key_prefix, name, created_at, last_used, revoked FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        ) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return rows
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error listing API keys: {e}")
        return []


async def revoke_api_key(user_id: int, key_id: int) -> bool:
    """软删除（revoked=1），仅允许操作自己的 key"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ? AND revoked = 0",
            (key_id, user_id)
        )
        await db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error revoking API key: {e}")
        return False


async def admin_list_all_api_keys(page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """管理员查看所有用户的 API Keys"""
    try:
        db = await get_db()
        async with db.execute("SELECT COUNT(*) FROM api_keys") as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute("""
            SELECT ak.id, ak.user_id, u.username, ak.key_prefix, ak.name,
                   ak.created_at, ak.last_used, ak.revoked
            FROM api_keys ak LEFT JOIN users u ON ak.user_id = u.id
            ORDER BY ak.created_at DESC LIMIT ? OFFSET ?
        """, (per_page, offset)) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error admin list API keys: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


async def admin_create_api_key(user_id: int, name: str = "") -> Optional[str]:
    """管理员为任意用户创建 API Key，不受 MAX_KEYS_PER_USER 限制"""
    try:
        db = await get_db()
        raw_key = "ts_" + secrets.token_hex(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        key_prefix = raw_key[:8]
        await db.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?)",
            (user_id, key_hash, key_prefix, name)
        )
        await db.commit()
        return raw_key
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error admin creating API key: {e}")
        return None


# ========== 代理管理函数 ==========

async def add_proxy(protocol: str, address: str, username: str = "", password: str = "") -> Optional[int]:
    """添加代理，返回代理 ID"""
    try:
        db = await get_db()
        cursor = await db.execute(
            "INSERT INTO proxies (protocol, address, username, password) VALUES (?, ?, ?, ?)",
            (protocol, address, username, password)
        )
        await db.commit()
        return cursor.lastrowid
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error adding proxy: {e}")
        return None


async def list_proxies(enabled_only: bool = True, page: int = 1, per_page: int = 50) -> Dict[str, Any]:
    """分页列出代理"""
    try:
        db = await get_db()
        where = " WHERE enabled = 1" if enabled_only else ""
        async with db.execute(f"SELECT COUNT(*) FROM proxies{where}") as cursor:
            total = (await cursor.fetchone())[0]
        offset = (page - 1) * per_page
        rows = []
        async with db.execute(
            f"SELECT * FROM proxies{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ) as cursor:
            async for row in cursor:
                rows.append(dict(row))
        return {
            "items": rows, "total": total, "page": page,
            "per_page": per_page, "total_pages": max(1, (total + per_page - 1) // per_page)
        }
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error listing proxies: {e}")
        return {"items": [], "total": 0, "page": page, "per_page": per_page, "total_pages": 1}


async def update_proxy(proxy_id: int, **kwargs) -> bool:
    """更新代理属性"""
    try:
        allowed = {"protocol", "address", "username", "password", "enabled"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False
        db = await get_db()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [proxy_id]
        cursor = await db.execute(
            f"UPDATE proxies SET {set_clause} WHERE id = ?", values
        )
        await db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error updating proxy {proxy_id}: {e}")
        return False


async def delete_proxy(proxy_id: int) -> bool:
    """删除代理"""
    try:
        db = await get_db()
        cursor = await db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
        await db.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error deleting proxy {proxy_id}: {e}")
        return False


async def get_next_proxy() -> Optional[Dict[str, Any]]:
    """轮询获取下一个可用代理（最久未使用优先）"""
    try:
        db = await get_db()
        async with db.execute(
            "SELECT * FROM proxies WHERE enabled = 1 ORDER BY last_used IS NOT NULL, last_used ASC LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
        return None
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error getting next proxy: {e}")
        return None


async def mark_proxy_used(proxy_id: int) -> None:
    """标记代理已使用"""
    try:
        db = await get_db()
        await db.execute(
            "UPDATE proxies SET last_used = CURRENT_TIMESTAMP WHERE id = ?", (proxy_id,)
        )
        await db.commit()
    except Exception as e:
        logging.getLogger("TurnstileAPIServer").error(f"Error marking proxy used {proxy_id}: {e}")
