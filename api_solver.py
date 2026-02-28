import os
import sys
import time
import uuid
import random
import secrets
import json
import html
import ipaddress
import socket
import logging
import asyncio
from urllib.parse import urlparse
from typing import Optional, Union
import argparse
from quart import Quart, request, jsonify, session, redirect, g
from camoufox.async_api import AsyncCamoufox
from patchright.async_api import async_playwright
from db_results import (
    init_db, close_db, save_result, load_result, cleanup_old_results, load_recent_results,
    get_task_stats, upsert_user, get_user_by_id, get_all_users,
    CREDIT_COST_PER_TASK, CREDIT_EXCHANGE_RATE,
    init_user_credits, get_user_credits, deduct_credits, refund_credits, add_credits,
    get_credit_log, daily_checkin, get_checkin_status,
    create_order, get_order_by_trade_no, update_order_paid, get_user_orders,
    admin_get_all_credits, admin_adjust_credits, admin_get_all_orders,
    create_api_key, list_api_keys, revoke_api_key, admin_list_all_api_keys,
    admin_create_api_key,
    add_proxy, list_proxies, update_proxy, delete_proxy, get_next_proxy, mark_proxy_used,
)
from browser_configs import browser_config
from auth import (
    get_oauth_config, oauth_configured, build_authorize_url, exchange_code_for_token,
    fetch_user_info, verify_admin, require_admin, require_user, require_api_key, generate_state,
    close_http_client, get_api_key_user_id,
)
from credit import (
    credit_configured, get_credit_config, verify_sign, generate_out_trade_no,
    build_payment_url,
)
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box



COLORS = {
    'MAGENTA': '\033[35m',
    'BLUE': '\033[34m',
    'GREEN': '\033[32m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'RESET': '\033[0m',
}


class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime('%H:%M:%S')
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message('DEBUG', 'MAGENTA', message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message('INFO', 'BLUE', message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message('SUCCESS', 'GREEN', message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(self.format_message('WARNING', 'YELLOW', message), *args, **kwargs)

    def error(self, message, *args, **kwargs):
        super().error(self.format_message('ERROR', 'RED', message), *args, **kwargs)


logging.setLoggerClass(CustomLogger)
logger = logging.getLogger("TurnstileAPIServer")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)


class TurnstileAPIServer:

    def __init__(self, headless: bool, useragent: Optional[str], debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool = False, browser_name: Optional[str] = None, browser_version: Optional[str] = None):
        self.app = Quart(__name__)
        secret_key = os.environ.get("SECRET_KEY")
        self.app.secret_key = secret_key if secret_key else secrets.token_hex(32)
        self.app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE="Lax",
        )
        if os.environ.get("SESSION_COOKIE_SECURE", "").lower() in ("1", "true", "yes"):
            self.app.config["SESSION_COOKIE_SECURE"] = True
        self.debug = debug
        self.browser_type = browser_type
        self.headless = headless
        self.thread_count = thread
        self.proxy_support = proxy_support
        self.browser_pool = asyncio.Queue()
        self.use_random_config = use_random_config
        self.browser_name = browser_name
        self.browser_version = browser_version
        self._pool_rebuilding = False
        self.console = Console()
        
        # 初始化 useragent 和 sec_ch_ua 属性
        self.useragent = useragent
        self.sec_ch_ua = None
        
        
        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            if browser_name and browser_version:
                config = browser_config.get_browser_config(browser_name, browser_version)
                if config:
                    useragent, sec_ch_ua = config
                    self.useragent = useragent
                    self.sec_ch_ua = sec_ch_ua
            elif useragent:
                self.useragent = useragent
            else:
                browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                self.browser_name = browser
                self.browser_version = version
                self.useragent = useragent
                self.sec_ch_ua = sec_ch_ua
        
        self.browser_args = []
        if self.useragent:
            self.browser_args.append(f"--user-agent={self.useragent}")

        self._setup_routes()

    def display_welcome(self):
        """显示带有 Logo 的欢迎界面"""
        self.console.clear()
        
        combined_text = Text()
        combined_text.append("\n版本: ", style="bold white")
        combined_text.append("1.2b", style="green")
        combined_text.append("\n")

        info_panel = Panel(
            Align.left(combined_text),
            title="[bold blue]Turnstile Solver[/bold blue]",
            box=box.ROUNDED,
            border_style="bright_blue",
            padding=(0, 1),
            width=50
        )

        self.console.print(info_panel)
        self.console.print()




    def _setup_routes(self) -> None:
        """设置应用路由"""
        self.app.before_serving(self._startup)
        self.app.after_serving(self._shutdown)
        self.app.route('/turnstile', methods=['GET'])(require_api_key(self.process_turnstile))
        self.app.route('/result', methods=['GET'])(require_api_key(self.get_result))
        self.app.route('/')(self.index)
        # 认证路由
        self.app.route('/auth/login')(self.auth_login_page)
        self.app.route('/auth/callback')(self.auth_callback)
        self.app.route('/auth/logout')(self.auth_logout)
        # 管理员登录路由
        self.app.route('/admin/login', methods=['GET', 'POST'])(self.admin_login)
        self.app.route('/admin/logout')(self.admin_logout)
        # 管理界面路由（需要管理员认证）
        self.app.route('/admin/')(require_admin(self.admin_page))
        self.app.route('/admin/api/status')(require_admin(self.admin_status))
        self.app.route('/admin/api/tasks')(require_admin(self.admin_tasks))
        self.app.route('/admin/api/config', methods=['POST'])(require_admin(self.admin_update_config))
        self.app.route('/admin/api/restart-pool', methods=['POST'])(require_admin(self.admin_restart_pool))
        self.app.route('/admin/api/cleanup', methods=['POST'])(require_admin(self.admin_cleanup))
        self.app.route('/admin/api/users')(require_admin(self.admin_users))
        # 用户仪表盘路由
        self.app.route('/dashboard/')(require_user(self.user_dashboard))
        self.app.route('/api/user/credits')(require_user(self.api_user_credits))
        self.app.route('/api/user/checkin', methods=['POST'])(require_user(self.api_user_checkin))
        self.app.route('/api/user/credit-log')(require_user(self.api_user_credit_log))
        self.app.route('/api/user/recharge', methods=['POST'])(require_user(self.api_user_recharge))
        self.app.route('/api/user/orders')(require_user(self.api_user_orders))
        # 支付回调（无认证，EasyPay 平台调用）
        self.app.route('/pay/notify', methods=['GET'])(self.pay_notify)
        self.app.route('/pay/return', methods=['GET'])(self.pay_return)
        # 管理员积分管理
        self.app.route('/admin/api/credits')(require_admin(self.admin_credits_list))
        self.app.route('/admin/api/credits/adjust', methods=['POST'])(require_admin(self.admin_credits_adjust))
        self.app.route('/admin/api/orders')(require_admin(self.admin_orders_list))
        # API Key 管理路由（仅 session 登录用户可操作）
        self.app.route('/api/user/keys', methods=['GET'])(require_user(self.api_user_keys_list))
        self.app.route('/api/user/keys', methods=['POST'])(require_user(self.api_user_keys_create))
        self.app.route('/api/user/keys/<int:key_id>/revoke', methods=['POST'])(require_user(self.api_user_keys_revoke))
        # 管理员 API Key 查看
        self.app.route('/admin/api/keys')(require_admin(self.admin_api_keys_list))
        # 管理员代理管理
        self.app.route('/admin/api/proxies', methods=['GET'])(require_admin(self.admin_proxies_list))
        self.app.route('/admin/api/proxies', methods=['POST'])(require_admin(self.admin_proxies_add))
        self.app.route('/admin/api/proxies/<int:proxy_id>', methods=['PUT'])(require_admin(self.admin_proxies_update))
        self.app.route('/admin/api/proxies/<int:proxy_id>', methods=['DELETE'])(require_admin(self.admin_proxies_delete))
        # 管理员为用户创建 Key
        self.app.route('/admin/api/keys/create', methods=['POST'])(require_admin(self.admin_keys_create))
        

    @staticmethod
    def _parse_ipv4ish(hostname: str) -> Optional[ipaddress.IPv4Address]:
        """解析浏览器可能接受的 IPv4 变体（如 127.1、2130706433）。"""
        host = (hostname or "").strip()
        if not host:
            return None

        # 整数形式：例如 2130706433 == 127.0.0.1
        if host.isdigit():
            try:
                value = int(host, 10)
            except ValueError:
                return None
            if 0 <= value <= 2**32 - 1:
                return ipaddress.IPv4Address(value)
            return None

        # 点分形式（socket.inet_aton 支持 127.1/127/等缩写）
        if all(ch.isdigit() or ch == "." for ch in host):
            try:
                packed = socket.inet_aton(host)
                return ipaddress.IPv4Address(packed)
            except OSError:
                return None

        return None

    @classmethod
    def _is_private_host(cls, hostname: str) -> bool:
        if not hostname:
            return True

        host = hostname.strip().lower().rstrip(".")
        if host in ("localhost",) or host.endswith(".localhost"):
            return True
        if host.endswith(".local") or host.endswith(".internal"):
            return True

        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = cls._parse_ipv4ish(host)

        if ip is None:
            return False

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )

    def _validate_target_url(self, url: str) -> tuple[bool, str]:
        """基础 SSRF 防护：仅允许 http(s) 且默认禁止本机/内网地址。"""
        if not isinstance(url, str):
            return False, "Invalid url"

        url = url.strip()
        if not url:
            return False, "Invalid url"
        if len(url) > 2048:
            return False, "URL too long"

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Only http/https URLs are allowed"
        if not parsed.hostname:
            return False, "Invalid URL"
        if parsed.username or parsed.password:
            return False, "URL must not include credentials"

        allow_private = os.environ.get("ALLOW_PRIVATE_URLS", "").lower() in ("1", "true", "yes")
        if not allow_private and self._is_private_host(parsed.hostname):
            return False, "Private/localhost URLs are not allowed"

        return True, ""

    async def _startup(self) -> None:
        """启动时初始化浏览器和页面池"""
        self.display_welcome()
        logger.info("Starting browser initialization")
        try:
            await init_db()
            await self._initialize_browser()
            
            # 启动定期清理旧结果的任务
            asyncio.create_task(self._periodic_cleanup())
            
        except Exception as e:
            logger.error(f"Failed to initialize browser: {str(e)}")
            raise

    async def _shutdown(self) -> None:
        """关闭时清理资源"""
        await close_db()
        await close_http_client()

    async def _initialize_browser(self) -> None:
        """初始化浏览器并创建页面池"""
        playwright = None
        camoufox = None

        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            playwright = await async_playwright().start()
        elif self.browser_type == "camoufox":
            camoufox = AsyncCamoufox(headless=self.headless)

        browser_configs = []
        for _ in range(self.thread_count):
            if self.browser_type in ['chromium', 'chrome', 'msedge']:
                if self.use_random_config:
                    browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                elif self.browser_name and self.browser_version:
                    config = browser_config.get_browser_config(self.browser_name, self.browser_version)
                    if config:
                        useragent, sec_ch_ua = config
                        browser = self.browser_name
                        version = self.browser_version
                    else:
                        browser, version, useragent, sec_ch_ua = browser_config.get_random_browser_config(self.browser_type)
                else:
                    browser = getattr(self, 'browser_name', 'custom')
                    version = getattr(self, 'browser_version', 'custom')
                    useragent = self.useragent
                    sec_ch_ua = getattr(self, 'sec_ch_ua', '')
            else:
                # 对于 camoufox 和其他浏览器使用默认值
                browser = self.browser_type
                version = 'custom'
                useragent = self.useragent
                sec_ch_ua = getattr(self, 'sec_ch_ua', '')

            
            browser_configs.append({
                'browser_name': browser,
                'browser_version': version,
                'useragent': useragent,
                'sec_ch_ua': sec_ch_ua
            })

        for i in range(self.thread_count):
            config = browser_configs[i]
            
            browser_args = []
            if config['useragent']:
                browser_args.append(f"--user-agent={config['useragent']}")
            
            browser = None
            if self.browser_type in ['chromium', 'chrome', 'msedge'] and playwright:
                browser = await playwright.chromium.launch(
                    channel=self.browser_type,
                    headless=self.headless,
                    args=browser_args
                )
            elif self.browser_type == "camoufox" and camoufox:
                browser = await camoufox.start()

            if browser:
                await self.browser_pool.put((i+1, browser, config))

            if self.debug:
                logger.info(f"Browser {i + 1} initialized successfully with {config['browser_name']} {config['browser_version']}")

        logger.info(f"Browser pool initialized with {self.browser_pool.qsize()} browsers")
        
        if self.use_random_config:
            logger.info(f"Each browser in pool received random configuration")
        elif self.browser_name and self.browser_version:
            logger.info(f"All browsers using configuration: {self.browser_name} {self.browser_version}")
        else:
            logger.info("Using custom configuration")
            
        if self.debug:
            for i, config in enumerate(browser_configs):
                logger.debug(f"Browser {i+1} config: {config['browser_name']} {config['browser_version']}")
                logger.debug(f"Browser {i+1} User-Agent: {config['useragent']}")
                logger.debug(f"Browser {i+1} Sec-CH-UA: {config['sec_ch_ua']}")

    async def _periodic_cleanup(self):
        """每小时定期清理旧结果"""
        while True:
            try:
                await asyncio.sleep(3600)
                deleted_count = await cleanup_old_results(days_old=7)
                if deleted_count > 0:
                    logger.info(f"Cleaned up {deleted_count} old results")
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")

    async def _rebuild_browser_pool(self):
        """排空并关闭空闲浏览器，用新配置重建池"""
        if self._pool_rebuilding:
            return
        self._pool_rebuilding = True
        try:
            logger.info("Rebuilding browser pool...")
            # 排空并关闭所有空闲浏览器
            closed = 0
            while not self.browser_pool.empty():
                try:
                    _idx, browser, _cfg = self.browser_pool.get_nowait()
                    try:
                        await browser.close()
                    except Exception:
                        pass
                    closed += 1
                except asyncio.QueueEmpty:
                    break
            logger.info(f"Closed {closed} idle browsers")

            # 替换队列
            self.browser_pool = asyncio.Queue()

            # 用当前配置重新初始化
            await self._initialize_browser()
            logger.info("Browser pool rebuilt successfully")
        except Exception as e:
            logger.error(f"Error rebuilding browser pool: {e}")
        finally:
            self._pool_rebuilding = False

    async def _antishadow_inject(self, page):
        await page.add_init_script("""
          (function() {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
              const shadow = originalAttachShadow.call(this, init);
              if (init.mode === 'closed') {
                window.__lastClosedShadowRoot = shadow;
              }
              return shadow;
            };
          })();
        """)



    async def _optimized_route_handler(self, route):
        """优化的路由处理器，用于节省资源"""
        url = route.request.url
        resource_type = route.request.resource_type

        allowed_types = {'document', 'script', 'xhr', 'fetch'}

        allowed_domains = [
            'challenges.cloudflare.com',
            'static.cloudflareinsights.com',
            'cloudflare.com'
        ]
        
        if resource_type in allowed_types:
            await route.continue_()
        elif any(domain in url for domain in allowed_domains):
            await route.continue_() 
        else:
            await route.abort()

    async def _block_rendering(self, page):
        """阻止渲染以节省资源"""
        await page.route("**/*", self._optimized_route_handler)

    async def _unblock_rendering(self, page):
        """解除渲染阻止"""
        await page.unroute("**/*", self._optimized_route_handler)

    async def _find_turnstile_elements(self, page, index: int):
        """智能检测所有可能的 Turnstile 元素"""
        selectors = [
            '.cf-turnstile',
            '[data-sitekey]',
            'iframe[src*="turnstile"]',
            'iframe[title*="widget"]',
            'div[id*="turnstile"]',
            'div[class*="turnstile"]'
        ]
        
        elements = []
        for selector in selectors:
            try:
                # 安全检查 count()
                try:
                    count = await page.locator(selector).count()
                except Exception:
                    # 如果 count() 出错，跳过该选择器
                    continue
                    
                if count > 0:
                    elements.append((selector, count))
                    if self.debug:
                        logger.debug(f"Browser {index}: Found {count} elements with selector '{selector}'")
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Selector '{selector}' failed: {str(e)}")
                continue
        
        return elements

    async def _find_and_click_checkbox(self, page, index: int):
        """在 iframe 中查找并点击 Turnstile CAPTCHA 复选框"""
        try:
            # 尝试不同的 iframe 选择器（带错误保护）
            iframe_selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                'iframe[title*="widget"]'
            ]
            
            iframe_locator = None
            for selector in iframe_selectors:
                try:
                    test_locator = page.locator(selector).first
                    # 安全检查 iframe 的 count
                    try:
                        iframe_count = await test_locator.count()
                    except Exception:
                        iframe_count = 0
                        
                    if iframe_count > 0:
                        iframe_locator = test_locator
                        if self.debug:
                            logger.debug(f"Browser {index}: Found Turnstile iframe with selector: {selector}")
                        break
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Iframe selector '{selector}' failed: {str(e)}")
                    continue
            
            if iframe_locator:
                try:
                    # 从 iframe 获取 frame
                    iframe_element = await iframe_locator.element_handle()
                    frame = await iframe_element.content_frame()
                    
                    if frame:
                        # 在 iframe 中查找复选框
                        checkbox_selectors = [
                            'input[type="checkbox"]',
                            '.cb-lb input[type="checkbox"]',
                            'label input[type="checkbox"]'
                        ]
                        
                        for selector in checkbox_selectors:
                            try:
                                # 完全避免在 iframe 中使用 locator.count() - 使用替代方案
                                try:
                                    # 尝试直接点击，不进行 count 检查
                                    checkbox = frame.locator(selector).first
                                    await checkbox.click(timeout=2000)
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Successfully clicked checkbox in iframe with selector '{selector}'")
                                    return True
                                except Exception as click_e:
                                    # 如果直接点击失败，记录调试信息但不崩溃
                                    if self.debug:
                                        logger.debug(f"Browser {index}: Direct checkbox click failed for '{selector}': {str(click_e)}")
                                    continue
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Iframe checkbox selector '{selector}' failed: {str(e)}")
                                continue
                    
                        # 如果找到了 iframe 但无法点击复选框，尝试直接点击 iframe
                        try:
                            if self.debug:
                                logger.debug(f"Browser {index}: Trying to click iframe directly as fallback")
                            await iframe_locator.click(timeout=1000)
                            return True
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Iframe direct click failed: {str(e)}")
                
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Failed to access iframe content: {str(e)}")
            
        except Exception as e:
            if self.debug:
                logger.debug(f"Browser {index}: General iframe search failed: {str(e)}")
        
        return False

    async def _try_click_strategies(self, page, index: int):
        strategies = [
            ('checkbox_click', lambda: self._find_and_click_checkbox(page, index)),
            ('direct_widget', lambda: self._safe_click(page, '.cf-turnstile', index)),
            ('iframe_click', lambda: self._safe_click(page, 'iframe[src*="turnstile"]', index)),
            ('js_click', lambda: page.evaluate("document.querySelector('.cf-turnstile')?.click()")),
            ('sitekey_attr', lambda: self._safe_click(page, '[data-sitekey]', index)),
            ('any_turnstile', lambda: self._safe_click(page, '*[class*="turnstile"]', index)),
            ('xpath_click', lambda: self._safe_click(page, "//div[@class='cf-turnstile']", index))
        ]
        
        for strategy_name, strategy_func in strategies:
            try:
                result = await strategy_func()
                if result is True or result is None:  # None означает успех для большинства стратегий
                    if self.debug:
                        logger.debug(f"Browser {index}: Click strategy '{strategy_name}' succeeded")
                    return True
            except Exception as e:
                if self.debug:
                    logger.debug(f"Browser {index}: Click strategy '{strategy_name}' failed: {str(e)}")
                continue
        
        return False

    async def _safe_click(self, page, selector: str, index: int):
        """完全安全的点击操作，具有最大的错误保护"""
        try:
            # 尝试直接点击，不进行 count() 检查
            locator = page.locator(selector).first
            await locator.click(timeout=1000)
            return True
        except Exception as e:
            # 仅在调试模式下记录错误
            if self.debug and "Can't query n-th element" not in str(e):
                logger.debug(f"Browser {index}: Safe click failed for '{selector}': {str(e)}")
            return False

    async def _load_captcha_overlay(self, page, websiteKey: str, action: str = '', index: int = 0):
        sitekey_js = json.dumps(websiteKey)
        action_js = json.dumps(action or "")
        script = f"""
        const existing = document.querySelector('#captcha-overlay');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'captcha-overlay';
        overlay.style.position = 'absolute';
        overlay.style.top = '0';
        overlay.style.left = '0';
        overlay.style.width = '100vw';
        overlay.style.height = '100vh';
        overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
        overlay.style.display = 'block';
        overlay.style.justifyContent = 'center';
        overlay.style.alignItems = 'center';
        overlay.style.zIndex = '1000';

        const captchaDiv = document.createElement('div');
        captchaDiv.className = 'cf-turnstile';
        captchaDiv.setAttribute('data-sitekey', {sitekey_js});
        captchaDiv.setAttribute('data-callback', 'onCaptchaSuccess');
        captchaDiv.setAttribute('data-action', {action_js});

        overlay.appendChild(captchaDiv);
        document.body.appendChild(overlay);

        const script = document.createElement('script');
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
        script.async = true;
        script.defer = true;
        document.head.appendChild(script);
        """

        await page.evaluate(script)
        if self.debug:
            logger.debug(f"Browser {index}: Created CAPTCHA overlay with sitekey: {websiteKey}")

    async def _solve_turnstile(self, task_id: str, url: str, sitekey: str, action: Optional[str] = None, cdata: Optional[str] = None, user_id: Optional[int] = None):
        """求解 Turnstile 验证"""
        proxy = None

        index, browser, browser_config = await self.browser_pool.get()
        
        try:
            if hasattr(browser, 'is_connected') and not browser.is_connected():
                if self.debug:
                    logger.warning(f"Browser {index}: Browser disconnected, skipping")
                await self.browser_pool.put((index, browser, browser_config))
                await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": 0})
                if user_id:
                    await refund_credits(user_id, CREDIT_COST_PER_TASK, "求解失败退款", task_id)
                return
        except Exception as e:
            if self.debug:
                logger.warning(f"Browser {index}: Cannot check browser state: {str(e)}")

        if self.proxy_support:
            proxy_record = await get_next_proxy()
            if proxy_record:
                proxy = self._build_proxy_url(proxy_record)
                await mark_proxy_used(proxy_record['id'])
                if self.debug:
                    logger.debug(f"Browser {index}: Selected proxy from DB: {proxy_record['address']}")
            else:
                if self.debug:
                    logger.debug(f"Browser {index}: No proxies available in DB")
                proxy = None

            if proxy:
                if '@' in proxy:
                    try:
                        scheme_part, auth_part = proxy.split('://')
                        auth, address = auth_part.split('@')
                        username, password = auth.split(':')
                        ip, port = address.split(':')
                        if self.debug:
                            logger.debug(f"Browser {index}: Creating context with proxy {scheme_part}://{ip}:{port} (auth: {username}:***)")
                        context_options = {
                            "proxy": {
                                "server": f"{scheme_part}://{ip}:{port}",
                                "username": username,
                                "password": password
                            },
                            "user_agent": browser_config['useragent']
                        }
                        
                        if browser_config['sec_ch_ua'] and browser_config['sec_ch_ua'].strip():
                            context_options['extra_http_headers'] = {
                                'sec-ch-ua': browser_config['sec_ch_ua']
                            }
                        
                        context = await browser.new_context(**context_options)
                    except ValueError:
                        raise ValueError(f"Invalid proxy format: {proxy}")
                else:
                    parts = proxy.split(':')
                    if len(parts) == 5:
                        proxy_scheme, proxy_ip, proxy_port, proxy_user, proxy_pass = parts
                        if self.debug:
                            logger.debug(f"Browser {index}: Creating context with proxy {proxy_scheme}://{proxy_ip}:{proxy_port} (auth: {proxy_user}:***)")
                        context_options = {
                            "proxy": {
                                "server": f"{proxy_scheme}://{proxy_ip}:{proxy_port}",
                                "username": proxy_user,
                                "password": proxy_pass
                            },
                            "user_agent": browser_config['useragent']
                        }
                        
                        if browser_config['sec_ch_ua'] and browser_config['sec_ch_ua'].strip():
                            context_options['extra_http_headers'] = {
                                'sec-ch-ua': browser_config['sec_ch_ua']
                            }
                        
                        context = await browser.new_context(**context_options)
                    elif len(parts) == 3:
                        if self.debug:
                            logger.debug(f"Browser {index}: Creating context with proxy {proxy}")
                        context_options = {
                            "proxy": {"server": f"{proxy}"},
                            "user_agent": browser_config['useragent']
                        }
                        
                        if browser_config['sec_ch_ua'] and browser_config['sec_ch_ua'].strip():
                            context_options['extra_http_headers'] = {
                                'sec-ch-ua': browser_config['sec_ch_ua']
                            }
                        
                        context = await browser.new_context(**context_options)
                    else:
                        raise ValueError(f"Invalid proxy format: {proxy}")
            else:
                if self.debug:
                    logger.debug(f"Browser {index}: Creating context without proxy")
                context_options = {"user_agent": browser_config['useragent']}
                
                if browser_config['sec_ch_ua'] and browser_config['sec_ch_ua'].strip():
                    context_options['extra_http_headers'] = {
                        'sec-ch-ua': browser_config['sec_ch_ua']
                    }
                
                context = await browser.new_context(**context_options)
        else:
            context_options = {"user_agent": browser_config['useragent']}
            
            if browser_config['sec_ch_ua'] and browser_config['sec_ch_ua'].strip():
                context_options['extra_http_headers'] = {
                    'sec-ch-ua': browser_config['sec_ch_ua']
                }
            
            context = await browser.new_context(**context_options)

        page = await context.new_page()
        
        #await self._antishadow_inject(page)
        
        await self._block_rendering(page)
        
        #await page.add_init_script("""
        #Object.defineProperty(navigator, 'webdriver', {
        #    get: () => undefined,
        #});
        
        #window.chrome = {
        #    runtime: {},
        #    loadTimes: function() {},
        #    csi: function() {},
        #};
        ##""")
        
        if self.browser_type in ['chromium', 'chrome', 'msedge']:
            await page.set_viewport_size({"width": 500, "height": 100})
            if self.debug:
                logger.debug(f"Browser {index}: Set viewport size to 500x240")

        start_time = time.time()

        try:
            if self.debug:
                logger.debug(f"Browser {index}: Starting Turnstile solve for URL: {url} with Sitekey: {sitekey} | Action: {action} | Cdata: {cdata} | Proxy: {proxy}")
                logger.debug(f"Browser {index}: Setting up optimized page loading with resource blocking")

            if self.debug:
                logger.debug(f"Browser {index}: Loading real website directly: {url}")

            await page.goto(url, wait_until='domcontentloaded', timeout=30000)

            await self._unblock_rendering(page)

            # 等待一段时间让 CAPTCHA 加载
            await asyncio.sleep(3)

            locator = page.locator('input[name="cf-turnstile-response"]')
            max_attempts = 20 
            
            for attempt in range(max_attempts):
                try:
                    # 安全检查带令牌的元素数量
                    try:
                        count = await locator.count()
                    except Exception as e:
                        if self.debug:
                            logger.debug(f"Browser {index}: Locator count failed on attempt {attempt + 1}: {str(e)}")
                        count = 0
                    
                    if count == 0:
                        if self.debug:
                            logger.debug(f"Browser {index}: No token elements found on attempt {attempt + 1}")
                    elif count == 1:
                        # 如果只有一个元素，检查其令牌
                        try:
                            token = await locator.input_value(timeout=500)
                            if token:
                                elapsed_time = round(time.time() - start_time, 3)
                                logger.success(f"Browser {index}: Successfully solved captcha - {COLORS.get('MAGENTA')}{token[:10]}{COLORS.get('RESET')} in {COLORS.get('GREEN')}{elapsed_time}{COLORS.get('RESET')} Seconds")
                                await save_result(task_id, "turnstile", {"value": token, "elapsed_time": elapsed_time})
                                return
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Single token element check failed: {str(e)}")
                    else:
                        # 如果有多个元素，逐一检查
                        if self.debug:
                            logger.debug(f"Browser {index}: Found {count} token elements, checking all")
                        
                        for i in range(count):
                            try:
                                element_token = await locator.nth(i).input_value(timeout=500)
                                if element_token:
                                    elapsed_time = round(time.time() - start_time, 3)
                                    logger.success(f"Browser {index}: Successfully solved captcha - {COLORS.get('MAGENTA')}{element_token[:10]}{COLORS.get('RESET')} in {COLORS.get('GREEN')}{elapsed_time}{COLORS.get('RESET')} Seconds")
                                    await save_result(task_id, "turnstile", {"value": element_token, "elapsed_time": elapsed_time})
                                    return
                            except Exception as e:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Token element {i} check failed: {str(e)}")
                                continue
                    
                    # 仅每隔3次尝试执行点击策略，且不在开始时执行
                    if attempt > 2 and attempt % 3 == 0:
                        click_success = await self._try_click_strategies(page, index)
                        if not click_success and self.debug:
                            logger.debug(f"Browser {index}: All click strategies failed on attempt {attempt + 1}")
                    
                    # Fallback overlay на 10 попытке если токена все еще нет
                    if attempt == 10:
                        try:
                            # 安全检查 overlay 的 count
                            try:
                                current_count = await locator.count()
                            except Exception:
                                current_count = 0
                                
                            if current_count == 0:
                                if self.debug:
                                    logger.debug(f"Browser {index}: Creating overlay as fallback strategy")
                                await self._load_captcha_overlay(page, sitekey, action or '', index)
                                await asyncio.sleep(2)
                        except Exception as e:
                            if self.debug:
                                logger.debug(f"Browser {index}: Fallback overlay creation failed: {str(e)}")
                    
                    # 自适应等待
                    wait_time = min(0.5 + (attempt * 0.05), 2.0)
                    await asyncio.sleep(wait_time)
                    
                    if self.debug and attempt % 5 == 0:
                        logger.debug(f"Browser {index}: Attempt {attempt + 1}/{max_attempts} - No valid token yet")
                        
                except Exception as e:
                    if self.debug:
                        logger.debug(f"Browser {index}: Attempt {attempt + 1} error: {str(e)}")
                    continue
            
            elapsed_time = round(time.time() - start_time, 3)
            await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed_time})
            if user_id:
                await refund_credits(user_id, CREDIT_COST_PER_TASK, "求解失败退款", task_id)
            if self.debug:
                logger.error(f"Browser {index}: Error solving Turnstile in {COLORS.get('RED')}{elapsed_time}{COLORS.get('RESET')} Seconds")
        except Exception as e:
            elapsed_time = round(time.time() - start_time, 3)
            await save_result(task_id, "turnstile", {"value": "CAPTCHA_FAIL", "elapsed_time": elapsed_time})
            if user_id:
                await refund_credits(user_id, CREDIT_COST_PER_TASK, "求解异常退款", task_id)
            if self.debug:
                logger.error(f"Browser {index}: Error solving Turnstile: {str(e)}")
        finally:
            if self.debug:
                logger.debug(f"Browser {index}: Closing browser context and cleaning up")
            
            try:
                await context.close()
                if self.debug:
                    logger.debug(f"Browser {index}: Context closed successfully")
            except Exception as e:
                if self.debug:
                    logger.warning(f"Browser {index}: Error closing context: {str(e)}")
            
            try:
                if hasattr(browser, 'is_connected') and browser.is_connected():
                    await self.browser_pool.put((index, browser, browser_config))
                    if self.debug:
                        logger.debug(f"Browser {index}: Browser returned to pool")
                else:
                    if self.debug:
                        logger.warning(f"Browser {index}: Browser disconnected, not returning to pool")
            except Exception as e:
                if self.debug:
                    logger.warning(f"Browser {index}: Error returning browser to pool: {str(e)}")






    async def process_turnstile(self):
        """处理 /turnstile 端点请求"""
        user_id = g.user_id

        url = request.args.get('url')
        sitekey = request.args.get('sitekey')
        action = request.args.get('action')
        cdata = request.args.get('cdata')

        if not url or not sitekey:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_PAGEURL",
                "errorDescription": "Both 'url' and 'sitekey' are required"
            }), 200

        ok, reason = self._validate_target_url(url)
        if not ok:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_PAGEURL",
                "errorDescription": reason,
            }), 200

        # 配额拦截：原子扣减积分
        if not await deduct_credits(user_id, CREDIT_COST_PER_TASK, "验证码求解", ""):
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_INSUFFICIENT_CREDITS",
                "errorDescription": "积分余额不足，请先充值"
            }), 402

        task_id = str(uuid.uuid4())
        await save_result(task_id, "turnstile", {
            "status": "CAPTCHA_NOT_READY",
            "createTime": int(time.time()),
            "url": url,
            "sitekey": sitekey,
            "action": action,
            "cdata": cdata
        })

        try:
            asyncio.create_task(self._solve_turnstile(task_id=task_id, url=url, sitekey=sitekey, action=action, cdata=cdata, user_id=user_id))

            if self.debug:
                logger.debug(f"Request completed with taskid {task_id}.")
            return jsonify({
                "errorId": 0,
                "taskId": task_id
            }), 200
        except Exception as e:
            logger.error(f"Unexpected error processing request: {str(e)}")
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_UNKNOWN",
                "errorDescription": str(e)
            }), 200

    async def get_result(self):
        """返回求解结果"""
        task_id = request.args.get('id')

        if not task_id:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_WRONG_CAPTCHA_ID",
                "errorDescription": "Invalid task ID/Request parameter"
            }), 200

        result = await load_result(task_id)
        if not result:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Task not found"
            }), 200

        if result == "CAPTCHA_NOT_READY" or (isinstance(result, dict) and result.get("status") == "CAPTCHA_NOT_READY"):
            return jsonify({"status": "processing"}), 200

        if isinstance(result, dict) and result.get("value") == "CAPTCHA_FAIL":
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Workers could not solve the Captcha"
            }), 200

        if isinstance(result, dict) and result.get("value") and result.get("value") != "CAPTCHA_FAIL":
            return jsonify({
                "errorId": 0,
                "status": "ready",
                "solution": {
                    "token": result["value"]
                }
            }), 200
        else:
            return jsonify({
                "errorId": 1,
                "errorCode": "ERROR_CAPTCHA_UNSOLVABLE",
                "errorDescription": "Workers could not solve the Captcha"
            }), 200

    

    async def index(self):
        """主页：登录页面"""
        # 已登录用户重定向到 dashboard
        if session.get("user_id"):
            return redirect("/dashboard/")

        oauth_enabled = oauth_configured()
        login_btn = ""
        if oauth_enabled:
            login_btn = '<a href="/auth/login" class="block w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition text-center">Linux DO 登录</a>'
        else:
            login_btn = '<p class="text-gray-500 text-sm text-center">OAuth 未配置</p>'

        return f"""
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Turnstile Solver</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-950 text-gray-200 min-h-screen flex items-center justify-center">
                <div class="bg-gray-900 border border-gray-700 rounded-lg p-8 max-w-sm w-full text-center">
                    <h1 class="text-2xl font-bold text-blue-400 mb-2">Turnstile Solver</h1>
                    <p class="text-gray-400 text-sm mb-6">Cloudflare Turnstile 验证码求解服务</p>
                    {login_btn}
                    <a href="/admin/login" class="block mt-4 text-xs text-gray-500 hover:text-gray-300">管理员登录</a>
                </div>
            </body>
            </html>
        """

    async def auth_login_page(self):
        """Linux DO OAuth 登录页面"""
        if not oauth_configured():
            return "<h1>OAuth 未配置</h1><p>请设置 LINUXDO_CLIENT_ID, LINUXDO_CLIENT_SECRET, LINUXDO_REDIRECT_URI 环境变量</p>", 500
        state = generate_state()
        session["oauth_state"] = state
        auth_url = build_authorize_url(state)
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>登录 - Turnstile Solver</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-950 text-gray-200 min-h-screen flex items-center justify-center">
<div class="bg-gray-900 border border-gray-700 rounded-lg p-8 max-w-sm w-full text-center">
<h1 class="text-2xl font-bold text-blue-400 mb-2">Turnstile Solver</h1>
<p class="text-gray-400 text-sm mb-6">使用 Linux DO 账号登录</p>
<a href="{auth_url}" class="block w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition">
Linux DO 登录</a>
<a href="/" class="block mt-4 text-xs text-gray-500 hover:text-gray-300">← 返回首页</a>
</div></body></html>"""

    async def auth_callback(self):
        """OAuth 回调处理"""
        code = request.args.get("code")
        state = request.args.get("state")
        if not code:
            return jsonify({"error": "missing code"}), 400
        saved_state = session.pop("oauth_state", None)
        if not state or state != saved_state:
            return jsonify({"error": "invalid state"}), 400

        token_data = await exchange_code_for_token(code)
        if not token_data or "access_token" not in token_data:
            return jsonify({"error": "token exchange failed"}), 500

        user_info = await fetch_user_info(token_data["access_token"])
        if not user_info or "id" not in user_info:
            return jsonify({"error": "failed to get user info"}), 500

        user = await upsert_user(user_info)
        if user:
            session["user_id"] = user["id"]
            session["linuxdo_id"] = user["linuxdo_id"]
            session["username"] = user["username"]
            session["trust_level"] = user["trust_level"]
            await init_user_credits(user["id"], user["trust_level"])
        return redirect("/dashboard/")

    async def auth_logout(self):
        """用户登出"""
        session.pop("user_id", None)
        session.pop("linuxdo_id", None)
        session.pop("username", None)
        session.pop("trust_level", None)
        return redirect("/")

    async def admin_login(self):
        """管理员登录页面和处理"""
        if session.get("is_admin"):
            return redirect("/admin/")

        error = ""
        if request.method == "POST":
            form = await request.form
            username = form.get("username", "")
            password = form.get("password", "")
            if verify_admin(username, password):
                session["is_admin"] = True
                return redirect("/admin/")
            error = "用户名或密码错误"

        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>管理员登录 - Turnstile Solver</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-950 text-gray-200 min-h-screen flex items-center justify-center">
<div class="bg-gray-900 border border-gray-700 rounded-lg p-8 max-w-sm w-full">
<h1 class="text-xl font-bold text-blue-400 mb-1 text-center">管理员登录</h1>
<p class="text-gray-500 text-xs mb-6 text-center">Turnstile Solver 管理面板</p>
{'<p class="text-red-400 text-sm mb-4 text-center">' + error + '</p>' if error else ''}
<form method="POST">
<div class="mb-4"><label class="block text-xs text-gray-400 mb-1">用户名</label>
<input name="username" type="text" required class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm focus:border-blue-500 outline-none"></div>
<div class="mb-6"><label class="block text-xs text-gray-400 mb-1">密码</label>
<input name="password" type="password" required class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm focus:border-blue-500 outline-none"></div>
<button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2.5 rounded-lg transition">登录</button>
</form>
<a href="/" class="block mt-4 text-xs text-gray-500 hover:text-gray-300 text-center">← 返回首页</a>
</div></body></html>"""

    async def admin_logout(self):
        """管理员登出"""
        session.pop("is_admin", None)
        return redirect("/admin/login")

    async def admin_page(self):
        """管理界面 HTML（缓存）"""
        if not hasattr(self, '_admin_page_html'):
            self._admin_page_html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Turnstile Solver - 管理面板</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@keyframes pulse-dot { 0%,100%{opacity:.4} 50%{opacity:1} }
.pulse-dot{animation:pulse-dot 1.5s infinite}
.toggle-checkbox:checked{right:0;border-color:#3b82f6}
.toggle-checkbox:checked+.toggle-label{background-color:#3b82f6}
.toggle-checkbox{right:1.25rem;transition:all .2s}
</style>
</head>
<body class="bg-gray-950 text-gray-200 min-h-screen">
<div class="max-w-7xl mx-auto px-4 py-6">
  <!-- 顶部栏 -->
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-blue-400">Turnstile Solver 管理面板</h1>
    <div class="flex items-center gap-3">
      <span id="rebuild-badge" class="hidden items-center gap-1 px-3 py-1 bg-yellow-600/30 text-yellow-300 rounded-full text-xs font-medium"><span class="pulse-dot inline-block w-2 h-2 rounded-full bg-yellow-400"></span>浏览器池重建中…</span>
      <span class="text-xs text-gray-400">管理员</span>
      <a href="/admin/logout" class="text-xs text-red-400 hover:text-red-300 transition">登出</a>
      <a href="/" class="text-sm text-gray-400 hover:text-blue-400 transition">← 返回首页</a>
    </div>
  </div>

  <!-- 统计卡片 -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4"><p class="text-xs text-gray-400 mb-1">浏览器池</p><p id="stat-pool" class="text-2xl font-bold text-blue-400">-</p></div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4"><p class="text-xs text-gray-400 mb-1">待处理</p><p id="stat-pending" class="text-2xl font-bold text-yellow-400">-</p></div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4"><p class="text-xs text-gray-400 mb-1">成功</p><p id="stat-success" class="text-2xl font-bold text-green-400">-</p></div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4"><p class="text-xs text-gray-400 mb-1">失败</p><p id="stat-failed" class="text-2xl font-bold text-red-400">-</p></div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- 左侧配置面板 -->
    <div class="lg:col-span-1 space-y-4">
      <!-- 即时配置 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">即时配置</h2>
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-sm">调试模式</span>
            <label class="relative inline-flex items-center cursor-pointer"><input type="checkbox" id="cfg-debug" class="toggle-checkbox sr-only peer" onchange="toggleConfig('debug',this.checked)"><div class="toggle-label w-10 h-5 bg-gray-600 rounded-full peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-5"></div></label>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm">代理支持</span>
            <label class="relative inline-flex items-center cursor-pointer"><input type="checkbox" id="cfg-proxy_support" class="toggle-checkbox sr-only peer" onchange="toggleConfig('proxy_support',this.checked)"><div class="toggle-label w-10 h-5 bg-gray-600 rounded-full peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-5"></div></label>
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm">随机UA配置</span>
            <label class="relative inline-flex items-center cursor-pointer"><input type="checkbox" id="cfg-use_random_config" class="toggle-checkbox sr-only peer" onchange="toggleConfig('use_random_config',this.checked)"><div class="toggle-label w-10 h-5 bg-gray-600 rounded-full peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-5"></div></label>
          </div>
        </div>
      </div>

      <!-- 浏览器池配置 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">浏览器池配置 <span class="text-xs text-yellow-500">（修改后需重启）</span></h2>
        <div class="space-y-3">
          <div>
            <label class="block text-xs text-gray-400 mb-1">浏览器类型</label>
            <select id="cfg-browser_type" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm focus:border-blue-500 outline-none">
              <option value="chromium">Chromium</option>
              <option value="chrome">Chrome</option>
              <option value="msedge">Edge</option>
              <option value="camoufox">Camoufox</option>
            </select>
          </div>
          <div>
            <label class="block text-xs text-gray-400 mb-1">并发数</label>
            <input id="cfg-thread_count" type="number" min="1" max="32" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm focus:border-blue-500 outline-none">
          </div>
          <div class="flex items-center justify-between">
            <span class="text-sm">无头模式</span>
            <label class="relative inline-flex items-center cursor-pointer"><input type="checkbox" id="cfg-headless" class="toggle-checkbox sr-only peer"><div class="toggle-label w-10 h-5 bg-gray-600 rounded-full peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-5"></div></label>
          </div>
          <div>
            <label class="block text-xs text-gray-400 mb-1">浏览器名称</label>
            <input id="cfg-browser_name" type="text" placeholder="例如 chrome" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm focus:border-blue-500 outline-none">
          </div>
          <div>
            <label class="block text-xs text-gray-400 mb-1">浏览器版本</label>
            <input id="cfg-browser_version" type="text" placeholder="例如 139" class="w-full bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm focus:border-blue-500 outline-none">
          </div>
          <button onclick="applyPoolConfig()" class="w-full mt-2 bg-blue-600 hover:bg-blue-700 text-white text-sm py-2 rounded transition font-medium">应用并重启浏览器池</button>
        </div>
      </div>

      <!-- 数据库维护 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">数据库维护</h2>
        <div class="flex gap-2">
          <select id="cleanup-days" class="bg-gray-800 border border-gray-600 rounded px-2 py-1.5 text-sm flex-1">
            <option value="1">1 天前</option>
            <option value="3">3 天前</option>
            <option value="7" selected>7 天前</option>
            <option value="30">30 天前</option>
          </select>
          <button onclick="cleanupDB()" class="bg-red-600/80 hover:bg-red-700 text-white text-sm px-4 py-1.5 rounded transition">清理</button>
        </div>
        <p id="cleanup-result" class="text-xs text-gray-500 mt-2 hidden"></p>
      </div>

      <!-- 用户管理 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-gray-300">已登录用户</h2>
          <span class="text-xs text-gray-500" id="user-total">共 0 人</span>
        </div>
        <div class="space-y-2 max-h-48 overflow-y-auto" id="user-list">
          <p class="text-xs text-gray-600">加载中…</p>
        </div>
      </div>

      <!-- 积分管理 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-gray-300">积分管理</h2>
          <span class="text-xs text-gray-500" id="credit-total">共 0 人</span>
        </div>
        <div class="space-y-2 max-h-48 overflow-y-auto" id="credit-list">
          <p class="text-xs text-gray-600">加载中…</p>
        </div>
        <div class="mt-3 border-t border-gray-700 pt-3">
          <p class="text-xs text-gray-400 mb-2">调整积分</p>
          <div class="flex gap-2">
            <input id="adj-uid" type="number" placeholder="用户ID" class="w-20 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            <input id="adj-amount" type="number" placeholder="积分(正/负)" class="w-24 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            <input id="adj-desc" type="text" placeholder="说明" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            <button onclick="adjustCredits()" class="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1 rounded transition">调整</button>
          </div>
          <p id="adj-result" class="text-xs text-gray-500 mt-1 hidden"></p>
        </div>
      </div>

      <!-- 代理管理 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-gray-300">代理管理</h2>
          <span class="text-xs text-gray-500" id="proxy-total">共 0 个</span>
        </div>
        <div class="space-y-2 max-h-48 overflow-y-auto" id="proxy-list">
          <p class="text-xs text-gray-600">加载中…</p>
        </div>
        <div class="mt-3 border-t border-gray-700 pt-3">
          <p class="text-xs text-gray-400 mb-2">添加代理</p>
          <div class="space-y-2">
            <div class="flex gap-2">
              <select id="proxy-protocol" class="w-20 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs">
                <option value="http">http</option>
                <option value="https">https</option>
                <option value="socks5">socks5</option>
              </select>
              <input id="proxy-address" type="text" placeholder="IP:端口" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            </div>
            <div class="flex gap-2">
              <input id="proxy-username" type="text" placeholder="用户名(可选)" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
              <input id="proxy-password" type="text" placeholder="密码(可选)" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            </div>
            <button onclick="addProxy()" class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs py-1.5 rounded transition">添加</button>
          </div>
          <p id="proxy-result" class="text-xs text-gray-500 mt-1 hidden"></p>
        </div>
      </div>

      <!-- 为用户创建 Key -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">为用户创建 API Key</h2>
        <div class="space-y-2">
          <div class="flex gap-2">
            <input id="ak-uid" type="number" placeholder="用户ID" class="w-24 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            <input id="ak-name" type="text" placeholder="Key名称" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
            <button onclick="adminCreateKey()" class="bg-blue-600 hover:bg-blue-700 text-white text-xs px-3 py-1 rounded transition">创建</button>
          </div>
          <div id="ak-result" class="hidden">
            <p class="text-xs text-gray-400 mb-1">创建成功，请妥善保存：</p>
            <input id="ak-key-display" type="text" readonly class="w-full bg-gray-800 border border-green-600 rounded px-2 py-1 text-xs text-green-400 font-mono">
          </div>
          <p id="ak-error" class="text-xs text-red-400 hidden"></p>
        </div>
      </div>
    </div>

    <!-- 右侧：任务列表 + 使用教程 -->
    <div class="lg:col-span-2 space-y-4">

      <!-- 管理员快捷操作 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">管理员快捷操作</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- 创建自己的 Key -->
          <div>
            <p class="text-xs text-gray-400 mb-2">创建我的 API Key</p>
            <div class="flex gap-2">
              <input id="self-key-name" type="text" placeholder="Key名称" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
              <button onclick="createSelfKey()" class="bg-green-600 hover:bg-green-700 text-white text-xs px-3 py-1 rounded transition">创建</button>
            </div>
            <div id="self-key-result" class="hidden mt-2">
              <input id="self-key-display" type="text" readonly class="w-full bg-gray-800 border border-green-600 rounded px-2 py-1 text-xs text-green-400 font-mono cursor-pointer" onclick="this.select();document.execCommand('copy')">
              <p class="text-[10px] text-gray-500 mt-1">点击复制，仅显示一次</p>
            </div>
            <p id="self-key-error" class="text-xs text-red-400 hidden mt-1"></p>
          </div>
          <!-- 给自己调积分 -->
          <div>
            <p class="text-xs text-gray-400 mb-2">调整我的积分</p>
            <div class="flex gap-2">
              <input id="self-credit-amount" type="number" placeholder="积分(正/负)" class="w-28 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
              <input id="self-credit-desc" type="text" placeholder="说明" class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs focus:border-blue-500 outline-none">
              <button onclick="adjustSelfCredits()" class="bg-green-600 hover:bg-green-700 text-white text-xs px-3 py-1 rounded transition">调整</button>
            </div>
            <p id="self-credit-result" class="text-xs hidden mt-1"></p>
          </div>
        </div>
      </div>

      <!-- 任务列表 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-gray-300">任务列表</h2>
          <div class="flex items-center gap-2">
            <select id="task-filter" class="bg-gray-800 border border-gray-600 rounded px-2 py-1 text-xs" onchange="currentPage=1;loadTasks()">
              <option value="all">全部</option>
              <option value="pending">待处理</option>
              <option value="success">成功</option>
              <option value="failed">失败</option>
            </select>
            <span class="text-xs text-gray-500" id="task-total">共 0 条</span>
          </div>
        </div>
        <div class="overflow-x-auto max-h-64 overflow-y-auto">
          <table class="w-full text-xs">
            <thead><tr class="text-gray-400 border-b border-gray-700"><th class="text-left py-2 px-2">任务ID</th><th class="text-left py-2 px-2">状态</th><th class="text-left py-2 px-2">耗时</th><th class="text-left py-2 px-2">创建时间</th></tr></thead>
            <tbody id="task-tbody"></tbody>
          </table>
        </div>
        <div class="flex items-center justify-between mt-3">
          <button onclick="prevPage()" id="btn-prev" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 disabled:cursor-not-allowed transition" disabled>上一页</button>
          <span id="page-info" class="text-xs text-gray-500">1 / 1</span>
          <button onclick="nextPage()" id="btn-next" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 disabled:cursor-not-allowed transition" disabled>下一页</button>
        </div>
      </div>

      <!-- API 使用教程 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">API 使用教程</h2>
        <div class="space-y-4 text-sm text-gray-300">
          <div>
            <h3 class="font-medium text-blue-400 mb-1">认证方式</h3>
            <p class="text-xs text-gray-400 mb-1">所有 API 请求需要使用 API Key 认证，支持两种方式：</p>
            <ul class="list-disc pl-6 space-y-0.5 text-gray-500 text-xs">
              <li>Header: <code class="bg-gray-800 px-1 rounded">Authorization: Bearer ts_xxx</code></li>
              <li>Query: <code class="bg-gray-800 px-1 rounded">?key=ts_xxx</code></li>
            </ul>
          </div>
          <div>
            <h3 class="font-medium text-blue-400 mb-1">1. 创建任务</h3>
            <div class="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-x-auto">GET /turnstile?url=https://example.com&amp;sitekey=YOUR_SITEKEY&amp;key=ts_xxx</div>
            <p class="text-[11px] text-gray-500 mt-1">参数：<code>url</code>（目标网址）、<code>sitekey</code>（站点密钥）、<code>action</code>（可选）、<code>cdata</code>（可选）</p>
            <p class="text-[11px] text-gray-500">返回：<code>{"errorId":0,"taskId":"uuid"}</code></p>
          </div>
          <div>
            <h3 class="font-medium text-blue-400 mb-1">2. 查询结果</h3>
            <div class="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-x-auto">GET /result?id=TASK_ID&amp;key=ts_xxx</div>
            <p class="text-[11px] text-gray-500 mt-1">处理中：<code>{"status":"processing"}</code></p>
            <p class="text-[11px] text-gray-500">成功：<code>{"errorId":0,"status":"ready","solution":{"token":"..."}}</code></p>
            <p class="text-[11px] text-gray-500">失败：<code>{"errorId":1,"errorCode":"ERROR_CAPTCHA_UNSOLVABLE"}</code></p>
          </div>
          <div>
            <h3 class="font-medium text-blue-400 mb-1">3. 完整流程示例（Python）</h3>
            <div class="bg-gray-800 rounded p-2 text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre">import requests, time

API = "https://your-domain.com"
KEY = "ts_xxxx"

# 创建任务
r = requests.get(f"{API}/turnstile", params={
    "url": "https://example.com",
    "sitekey": "0x4AAAAAAA...",
    "key": KEY
}).json()
task_id = r["taskId"]

# 轮询结果
for _ in range(60):
    r = requests.get(f"{API}/result", params={
        "id": task_id, "key": KEY
    }).json()
    if r.get("status") == "ready":
        print("Token:", r["solution"]["token"])
        break
    time.sleep(2)</div>
          </div>
        </div>
      </div>

    </div>
  </div>
</div>

<script>
let currentPage=1, totalPages=1, pollTimer=null, hasPending=false;

function escapeHtml(v){
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function api(path,opts){return fetch('/admin/api/'+path,opts).then(r=>r.json())}

async function loadStatus(){
  try{
    const d=await api('status');
    document.getElementById('stat-pool').textContent=d.pool_available+'/'+d.pool_total;
    document.getElementById('stat-pending').textContent=d.stats.pending;
    document.getElementById('stat-success').textContent=d.stats.success;
    document.getElementById('stat-failed').textContent=d.stats.failed;
    hasPending=d.stats.pending>0;
    document.getElementById('rebuild-badge').classList.toggle('hidden',!d.pool_rebuilding);
    document.getElementById('rebuild-badge').classList.toggle('flex',d.pool_rebuilding);
    // 同步配置到UI
    const c=d.config;
    document.getElementById('cfg-debug').checked=c.debug;
    document.getElementById('cfg-proxy_support').checked=c.proxy_support;
    document.getElementById('cfg-use_random_config').checked=c.use_random_config;
    document.getElementById('cfg-browser_type').value=c.browser_type;
    document.getElementById('cfg-thread_count').value=c.thread_count;
    document.getElementById('cfg-headless').checked=c.headless;
    document.getElementById('cfg-browser_name').value=c.browser_name||'';
    document.getElementById('cfg-browser_version').value=c.browser_version||'';
  }catch(e){console.error('loadStatus',e)}
}

async function loadTasks(){
  try{
    const filter=document.getElementById('task-filter').value;
    const d=await api('tasks?page='+currentPage+'&per_page=20&filter='+filter);
    totalPages=d.total_pages;
    document.getElementById('task-total').textContent='共 '+d.total+' 条';
    document.getElementById('page-info').textContent=d.page+' / '+d.total_pages;
    document.getElementById('btn-prev').disabled=(d.page<=1);
    document.getElementById('btn-next').disabled=(d.page>=d.total_pages);
    const tbody=document.getElementById('task-tbody');
    tbody.innerHTML='';
    d.items.forEach(t=>{
      let status,cls;
      if(typeof t.data==='object'){
        if(t.data.status==='CAPTCHA_NOT_READY'){status='待处理';cls='text-yellow-400'}
        else if(t.data.value==='CAPTCHA_FAIL'){status='失败';cls='text-red-400'}
        else if(t.data.value){status='成功';cls='text-green-400'}
        else{status='未知';cls='text-gray-400'}
      }else{status='未知';cls='text-gray-400'}
      const elapsed=t.data&&t.data.elapsed_time?t.data.elapsed_time+'s':'-';
      const tid=String(t.task_id||'');
      const tidShort=tid.substring(0,8)+'…';
      const tr=document.createElement('tr');
      tr.className='border-b border-gray-800 hover:bg-gray-800/50';
      tr.innerHTML='<td class="py-2 px-2 font-mono text-gray-400" title="'+escapeHtml(tid)+'">'+escapeHtml(tidShort)+'</td><td class="py-2 px-2"><span class="'+cls+'">'+escapeHtml(status)+'</span></td><td class="py-2 px-2">'+escapeHtml(elapsed)+'</td><td class="py-2 px-2 text-gray-500">'+escapeHtml(t.created_at||'-')+'</td>';
      tbody.appendChild(tr);
    });
    if(d.items.length===0){
      tbody.innerHTML='<tr><td colspan="4" class="text-center py-8 text-gray-600">暂无任务</td></tr>';
    }
  }catch(e){console.error('loadTasks',e)}
}

function prevPage(){if(currentPage>1){currentPage--;loadTasks()}}
function nextPage(){if(currentPage<totalPages){currentPage++;loadTasks()}}

async function toggleConfig(key,val){
  try{
    const payload={};payload[key]=val;
    await api('config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  }catch(e){console.error('toggleConfig',e)}
}

async function applyPoolConfig(){
  if(!confirm('确定要修改浏览器池配置并重启吗？\\n正在运行的任务不会被中断，但在重启期间新任务将排队等待。')) return;
  const payload={
    browser_type:document.getElementById('cfg-browser_type').value,
    thread_count:parseInt(document.getElementById('cfg-thread_count').value)||4,
    headless:document.getElementById('cfg-headless').checked,
    browser_name:document.getElementById('cfg-browser_name').value||null,
    browser_version:document.getElementById('cfg-browser_version').value||null
  };
  try{
    await api('config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    await api('restart-pool',{method:'POST'});
    loadStatus();
  }catch(e){console.error('applyPoolConfig',e)}
}

async function cleanupDB(){
  const days=document.getElementById('cleanup-days').value;
  try{
    const d=await api('cleanup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days_old:parseInt(days)})});
    const el=document.getElementById('cleanup-result');
    el.textContent='已清理 '+d.deleted+' 条记录';
    el.classList.remove('hidden');
    setTimeout(()=>el.classList.add('hidden'),5000);
    loadStatus();loadTasks();
  }catch(e){console.error('cleanupDB',e)}
}

async function loadUsers(){
  try{
    const d=await api('users');
    document.getElementById('user-total').textContent='共 '+d.total+' 人';
    const el=document.getElementById('user-list');
    if(d.items.length===0){el.innerHTML='<p class="text-xs text-gray-600">暂无用户</p>';return;}
    el.innerHTML=d.items.map(u=>'<div class="flex items-center justify-between text-xs py-1 border-b border-gray-800"><div class="flex items-center gap-2"><span class="text-gray-300">'+escapeHtml(u.username)+'</span><span class="text-gray-600">'+escapeHtml(u.name||'')+'</span></div><div class="flex items-center gap-2"><span class="px-1.5 py-0.5 rounded text-[10px] '+(u.trust_level>=2?'bg-green-900/50 text-green-400':'bg-gray-800 text-gray-400')+'">TL'+escapeHtml(u.trust_level)+'</span></div></div>').join('');
  }catch(e){console.error('loadUsers',e)}
}

async function loadCreditsAdmin(){
  try{
    const d=await api('credits');
    document.getElementById('credit-total').textContent='共 '+d.total+' 人';
    const el=document.getElementById('credit-list');
    if(d.items.length===0){el.innerHTML='<p class="text-xs text-gray-600">暂无数据</p>';return;}
    el.innerHTML=d.items.map(c=>'<div class="flex items-center justify-between text-xs py-1 border-b border-gray-800"><div class="flex items-center gap-2"><span class="text-gray-300">'+escapeHtml(c.username)+'</span><span class="text-gray-600">ID:'+escapeHtml(c.id)+'</span></div><div class="flex items-center gap-2"><span class="text-green-400 font-mono">'+escapeHtml(c.balance)+'</span><span class="text-gray-600">TL'+escapeHtml(c.trust_level)+'</span></div></div>').join('');
  }catch(e){console.error('loadCreditsAdmin',e)}
}

async function adjustCredits(){
  const uid=document.getElementById('adj-uid').value;
  const amount=document.getElementById('adj-amount').value;
  const desc=document.getElementById('adj-desc').value;
  const el=document.getElementById('adj-result');
  if(!uid||!amount){el.textContent='请填写用户ID和积分';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');return;}
  try{
    const d=await api('credits/adjust',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:parseInt(uid),amount:parseFloat(amount),description:desc})});
    if(d.success){el.textContent='调整成功';el.className='text-xs mt-1 text-green-400';loadCreditsAdmin();}
    else{el.textContent='调整失败';el.className='text-xs mt-1 text-red-400';}
    el.classList.remove('hidden');setTimeout(()=>el.classList.add('hidden'),3000);
  }catch(e){el.textContent='网络错误';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');}
}

function startPolling(){
  async function tick(){
    await Promise.all([loadStatus(),loadTasks()]);
    pollTimer=setTimeout(tick, hasPending?2000:5000);
  }
  tick();
  loadUsers();
  loadCreditsAdmin();
  loadProxies();
  setInterval(loadUsers,30000);
  setInterval(loadCreditsAdmin,30000);
  setInterval(loadProxies,30000);
}

async function loadProxies(){
  try{
    const d=await api('proxies');
    document.getElementById('proxy-total').textContent='共 '+d.total+' 个';
    const el=document.getElementById('proxy-list');
    if(d.items.length===0){el.innerHTML='<p class="text-xs text-gray-600">暂无代理</p>';return;}
    el.innerHTML=d.items.map(p=>{
      const status=p.enabled?'<span class="text-green-400">启用</span>':'<span class="text-red-400">禁用</span>';
      const auth=p.username?'<span class="text-gray-600">(有认证)</span>':'';
      return '<div class="flex items-center justify-between text-xs py-1 border-b border-gray-800"><div class="flex items-center gap-2"><span class="text-gray-400 font-mono">'+escapeHtml(p.protocol)+'://'+escapeHtml(p.address)+'</span>'+auth+'</div><div class="flex items-center gap-2">'+status+'<button onclick="toggleProxy('+p.id+','+(!p.enabled?1:0)+')" class="text-blue-400 hover:text-blue-300 text-[10px]">'+(p.enabled?'禁用':'启用')+'</button><button onclick="deleteProxy('+p.id+')" class="text-red-400 hover:text-red-300 text-[10px]">删除</button></div></div>';
    }).join('');
  }catch(e){console.error('loadProxies',e)}
}

async function addProxy(){
  const protocol=document.getElementById('proxy-protocol').value;
  const address=document.getElementById('proxy-address').value;
  const username=document.getElementById('proxy-username').value;
  const password=document.getElementById('proxy-password').value;
  const el=document.getElementById('proxy-result');
  if(!address){el.textContent='请填写地址';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');return;}
  try{
    const d=await api('proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({protocol,address,username,password})});
    if(d.id){el.textContent='添加成功';el.className='text-xs mt-1 text-green-400';loadProxies();document.getElementById('proxy-address').value='';document.getElementById('proxy-username').value='';document.getElementById('proxy-password').value='';}
    else{el.textContent=d.error||'添加失败';el.className='text-xs mt-1 text-red-400';}
    el.classList.remove('hidden');setTimeout(()=>el.classList.add('hidden'),3000);
  }catch(e){el.textContent='网络错误';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');}
}

async function toggleProxy(id,enabled){
  try{
    await api('proxies/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});
    loadProxies();
  }catch(e){console.error('toggleProxy',e)}
}

async function deleteProxy(id){
  if(!confirm('确定删除该代理？')) return;
  try{
    await api('proxies/'+id,{method:'DELETE'});
    loadProxies();
  }catch(e){console.error('deleteProxy',e)}
}

async function adminCreateKey(){
  const uid=document.getElementById('ak-uid').value;
  const name=document.getElementById('ak-name').value;
  const resultEl=document.getElementById('ak-result');
  const errorEl=document.getElementById('ak-error');
  resultEl.classList.add('hidden');errorEl.classList.add('hidden');
  if(!uid){errorEl.textContent='请填写用户ID';errorEl.classList.remove('hidden');return;}
  try{
    const d=await api('keys/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:parseInt(uid),name})});
    if(d.key){resultEl.classList.remove('hidden');document.getElementById('ak-key-display').value=d.key;}
    else{errorEl.textContent=d.error||'创建失败';errorEl.classList.remove('hidden');}
  }catch(e){errorEl.textContent='网络错误';errorEl.classList.remove('hidden');}
}

async function createSelfKey(){
  const name=document.getElementById('self-key-name').value;
  const resultEl=document.getElementById('self-key-result');
  const errorEl=document.getElementById('self-key-error');
  resultEl.classList.add('hidden');errorEl.classList.add('hidden');
  try{
    const d=await api('keys/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:'__ADMIN__',name})});
    if(d.key){resultEl.classList.remove('hidden');document.getElementById('self-key-display').value=d.key;}
    else{errorEl.textContent=d.error||'创建失败';errorEl.classList.remove('hidden');}
  }catch(e){errorEl.textContent='网络错误';errorEl.classList.remove('hidden');}
}

async function adjustSelfCredits(){
  const amount=document.getElementById('self-credit-amount').value;
  const desc=document.getElementById('self-credit-desc').value;
  const el=document.getElementById('self-credit-result');
  if(!amount){el.textContent='请填写积分';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');return;}
  try{
    const d=await api('credits/adjust',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:'__ADMIN__',amount:parseFloat(amount),description:desc||'管理员自调'})});
    if(d.success){el.textContent='调整成功';el.className='text-xs mt-1 text-green-400';loadCreditsAdmin();}
    else{el.textContent=d.error||'调整失败';el.className='text-xs mt-1 text-red-400';}
    el.classList.remove('hidden');setTimeout(()=>el.classList.add('hidden'),3000);
  }catch(e){el.textContent='网络错误';el.className='text-xs mt-1 text-red-400';el.classList.remove('hidden');}
}

startPolling();
</script>
</body>
</html>"""
        return self._admin_page_html

    async def admin_status(self):
        """系统状态 API"""
        stats = await get_task_stats()
        return jsonify({
            "pool_available": self.browser_pool.qsize(),
            "pool_total": self.thread_count,
            "pool_rebuilding": self._pool_rebuilding,
            "stats": stats,
            "config": {
                "debug": self.debug,
                "browser_type": self.browser_type,
                "headless": self.headless,
                "thread_count": self.thread_count,
                "proxy_support": self.proxy_support,
                "use_random_config": self.use_random_config,
                "browser_name": self.browser_name,
                "browser_version": self.browser_version,
            }
        })

    async def admin_tasks(self):
        """分页任务列表 API"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        task_filter = request.args.get('filter', 'all')

        data = await load_recent_results(page, per_page, status_filter=task_filter)

        return jsonify(data)

    async def admin_update_config(self):
        """修改配置 API"""
        body = await request.get_json()
        if not body:
            return jsonify({"error": "empty body"}), 400

        hot_keys = {"debug", "proxy_support", "use_random_config"}
        pool_keys = {"browser_type", "thread_count", "headless", "browser_name", "browser_version"}

        changed = []
        for key, val in body.items():
            if key in hot_keys:
                setattr(self, key, val)
                changed.append(key)
            elif key in pool_keys:
                setattr(self, key, val)
                changed.append(key)

        return jsonify({"updated": changed})

    async def admin_restart_pool(self):
        """手动触发浏览器池重启"""
        if self._pool_rebuilding:
            return jsonify({"status": "already_rebuilding"})
        asyncio.create_task(self._rebuild_browser_pool())
        return jsonify({"status": "rebuild_started"})

    async def admin_cleanup(self):
        """手动清理数据库旧数据"""
        body = await request.get_json() or {}
        try:
            days = int(body.get("days_old", 7))
        except (TypeError, ValueError):
            return jsonify({"error": "days_old must be an integer"}), 400
        days = max(1, min(days, 3650))
        deleted = await cleanup_old_results(days_old=days)
        return jsonify({"deleted": deleted})

    async def admin_users(self):
        """用户列表 API"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        data = await get_all_users(page, per_page)
        return jsonify(data)

    # ========== 用户积分仪表盘 ==========

    async def api_user_credits(self):
        """用户积分 API"""
        user_id = session["user_id"]
        credits = await get_user_credits(user_id)
        checkin = await get_checkin_status(user_id)
        return jsonify({"credits": credits, "checkin": checkin})

    async def api_user_checkin(self):
        """每日签到 API"""
        user_id = session["user_id"]
        trust_level = session.get("trust_level", 0)
        result = await daily_checkin(user_id, trust_level)
        if result is None:
            return jsonify({"error": "今日已签到"}), 400
        return jsonify(result)

    async def api_user_credit_log(self):
        """积分流水 API"""
        user_id = session["user_id"]
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 15, type=int)
        data = await get_credit_log(user_id, page, per_page)
        return jsonify(data)

    async def api_user_recharge(self):
        """创建充值订单 API"""
        if not credit_configured():
            return jsonify({"error": "充值功能未配置"}), 503
        body = await request.get_json()
        if not body:
            return jsonify({"error": "参数错误"}), 400
        money = body.get("money")
        try:
            money = float(money)
            if money < 1 or money > 10000:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "金额无效，请输入 1~10000"}), 400

        user_id = session["user_id"]
        amount = money * CREDIT_EXCHANGE_RATE
        cfg = get_credit_config()
        out_trade_no = generate_out_trade_no(user_id)

        order_id = await create_order(user_id, out_trade_no, money, amount)
        if not order_id:
            return jsonify({"error": "创建订单失败"}), 500

        notify_url = request.host_url.rstrip("/") + "/pay/notify"
        return_url = request.host_url.rstrip("/") + "/dashboard/"

        pay_url = build_payment_url(
            pid=cfg["pid"], key=cfg["key"],
            out_trade_no=out_trade_no,
            name=f"积分充值 {amount} 积分",
            money=f"{money:.2f}",
            notify_url=notify_url,
            return_url=return_url,
        )
        return jsonify({"pay_url": pay_url, "out_trade_no": out_trade_no})

    async def api_user_orders(self):
        """用户订单列表 API"""
        user_id = session["user_id"]
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        data = await get_user_orders(user_id, page, per_page)
        return jsonify(data)

    async def pay_notify(self):
        """EasyPay 异步通知回调"""
        params = dict(request.args)
        cfg = get_credit_config()
        if not cfg.get("key"):
            return "not configured", 503
        if not verify_sign(params, cfg["key"]):
            return "sign error", 400

        trade_status = params.get("trade_status", "")
        if trade_status != "TRADE_SUCCESS":
            return "fail"

        out_trade_no = params.get("out_trade_no", "")
        trade_no = params.get("trade_no", "")
        raw_notify = str(params)

        order = await get_order_by_trade_no(out_trade_no)
        if not order:
            return "order not found", 400

        updated = await update_order_paid(out_trade_no, trade_no, raw_notify)
        if updated:
            await add_credits(
                order["user_id"], order["amount"], "recharge",
                f"充值 {order['money']} 元", out_trade_no
            )
        return "success"

    async def pay_return(self):
        """EasyPay 同步跳转"""
        return redirect("/dashboard/")

    # ========== 管理员积分管理 ==========

    async def admin_credits_list(self):
        """管理员积分列表 API"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        data = await admin_get_all_credits(page, per_page)
        return jsonify(data)

    async def admin_credits_adjust(self):
        """管理员调整积分 API"""
        body = await request.get_json()
        if not body:
            return jsonify({"error": "参数错误"}), 400
        user_id = body.get("user_id")
        amount = body.get("amount")
        description = body.get("description", "")
        # __ADMIN__ 表示管理员调整自己的积分
        if user_id == "__ADMIN__":
            user_id = await self._ensure_admin_user()
            if not user_id:
                return jsonify({"error": "管理员用户初始化失败"}), 500
        elif not user_id:
            return jsonify({"error": "user_id 必填"}), 400
        else:
            user_id = int(user_id)
        if amount is None:
            return jsonify({"error": "amount 必填"}), 400
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return jsonify({"error": "amount 无效"}), 400
        ok = await admin_adjust_credits(user_id, amount, description)
        return jsonify({"success": ok})

    async def admin_orders_list(self):
        """管理员订单列表 API"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        data = await admin_get_all_orders(page, per_page)
        return jsonify(data)

    # ========== API Key 管理 ==========

    async def api_user_keys_list(self):
        """列出当前用户的 API Keys"""
        user_id = session.get("user_id") or g.get("user_id")
        if not user_id:
            return jsonify({"error": "unauthorized"}), 401
        keys = await list_api_keys(user_id)
        return jsonify({"keys": keys})

    async def api_user_keys_create(self):
        """创建新 API Key（仅 session 登录用户可操作）"""
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "仅登录用户可创建 API Key，不允许通过 API Key 创建"}), 403
        data = await request.get_json(silent=True) or {}
        name = str(data.get("name", ""))[:50]
        raw_key = await create_api_key(user_id, name)
        if raw_key is None:
            return jsonify({"error": "已达到最大 Key 数量限制（5 个）"}), 400
        return jsonify({"key": raw_key, "message": "请妥善保存，此密钥仅显示一次"})

    async def api_user_keys_revoke(self, key_id: int):
        """撤销指定 API Key"""
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "仅登录用户可撤销 API Key"}), 403
        ok = await revoke_api_key(user_id, key_id)
        if not ok:
            return jsonify({"error": "Key 不存在或已撤销"}), 404
        return jsonify({"message": "已撤销"})

    async def admin_api_keys_list(self):
        """管理员查看所有 API Keys"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        data = await admin_list_all_api_keys(page, per_page)
        return jsonify(data)

    # ========== 管理员代理管理 ==========

    async def admin_proxies_list(self):
        """列出所有代理"""
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        data = await list_proxies(enabled_only=False, page=page, per_page=per_page)
        return jsonify(data)

    async def admin_proxies_add(self):
        """添加代理"""
        body = await request.get_json()
        if not body:
            return jsonify({"error": "参数错误"}), 400
        address = body.get("address", "").strip()
        if not address:
            return jsonify({"error": "address 必填"}), 400
        protocol = body.get("protocol", "http").strip()
        username = body.get("username", "").strip()
        password = body.get("password", "").strip()
        proxy_id = await add_proxy(protocol, address, username, password)
        if proxy_id is None:
            return jsonify({"error": "添加失败"}), 500
        return jsonify({"id": proxy_id, "message": "添加成功"})

    async def admin_proxies_update(self, proxy_id: int):
        """更新代理"""
        body = await request.get_json()
        if not body:
            return jsonify({"error": "参数错误"}), 400
        ok = await update_proxy(proxy_id, **body)
        if not ok:
            return jsonify({"error": "更新失败"}), 404
        return jsonify({"message": "更新成功"})

    async def admin_proxies_delete(self, proxy_id: int):
        """删除代理"""
        ok = await delete_proxy(proxy_id)
        if not ok:
            return jsonify({"error": "删除失败"}), 404
        return jsonify({"message": "删除成功"})

    async def admin_keys_create(self):
        """管理员为指定用户创建 API Key"""
        body = await request.get_json()
        if not body:
            return jsonify({"error": "参数错误"}), 400
        user_id = body.get("user_id")
        name = str(body.get("name", ""))[:50]
        # __ADMIN__ 表示管理员为自己创建
        if user_id == "__ADMIN__":
            user_id = await self._ensure_admin_user()
            if not user_id:
                return jsonify({"error": "管理员用户初始化失败"}), 500
        else:
            if not user_id:
                return jsonify({"error": "user_id 必填"}), 400
            user_id = int(user_id)
            user = await get_user_by_id(user_id)
            if not user:
                return jsonify({"error": "用户不存在"}), 404
        raw_key = await admin_create_api_key(user_id, name)
        if raw_key is None:
            return jsonify({"error": "创建失败"}), 500
        return jsonify({"key": raw_key, "message": "创建成功，请妥善保存"})

    @staticmethod
    def _build_proxy_url(proxy_record: dict) -> str:
        """根据代理记录构建代理 URL"""
        protocol = proxy_record.get("protocol", "http")
        address = proxy_record.get("address", "")
        username = proxy_record.get("username", "")
        password = proxy_record.get("password", "")
        if username and password:
            return f"{protocol}://{username}:{password}@{address}"
        return f"{protocol}://{address}"

    async def _ensure_admin_user(self) -> Optional[int]:
        """确保管理员在 users 表中有记录，返回 user_id"""
        admin_user = await upsert_user({
            "id": 0,
            "username": "admin",
            "name": "管理员",
            "avatar_template": "",
            "trust_level": 4,
            "active": True,
            "silenced": False,
        })
        if admin_user:
            await init_user_credits(admin_user["id"], 4)
            return admin_user["id"]
        return None

    # ========== 用户仪表盘页面 ==========

    async def user_dashboard(self):
        """用户积分仪表盘页面（模板缓存）"""
        if not hasattr(self, '_dashboard_template'):
            self._dashboard_template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>我的积分 - Turnstile Solver</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@keyframes spin-fast { 0%{transform:rotate(0deg)} 100%{transform:rotate(360deg)} }
.spin-fast{animation:spin-fast .8s linear infinite}
</style>
</head>
<body class="bg-gray-950 text-gray-200 min-h-screen">
<div class="max-w-5xl mx-auto px-4 py-6">
  <!-- 顶部栏 -->
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-blue-400">我的积分</h1>
    <div class="flex items-center gap-3">
      <span class="text-sm text-gray-400">__USERNAME__</span>
      <a href="/" class="text-xs text-gray-400 hover:text-blue-400 transition">首页</a>
      <a href="/auth/logout" class="text-xs text-red-400 hover:text-red-300 transition">登出</a>
    </div>
  </div>

  <!-- 积分概览 -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <p class="text-xs text-gray-400 mb-1">积分余额</p>
      <p id="credit-balance" class="text-2xl font-bold text-green-400">-</p>
    </div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <p class="text-xs text-gray-400 mb-1">总获得</p>
      <p id="credit-earned" class="text-2xl font-bold text-blue-400">-</p>
    </div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <p class="text-xs text-gray-400 mb-1">总消耗</p>
      <p id="credit-spent" class="text-2xl font-bold text-yellow-400">-</p>
    </div>
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4 flex flex-col items-center justify-center">
      <button id="btn-checkin" onclick="doCheckin()" class="w-full bg-green-600 hover:bg-green-700 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm py-2.5 rounded-lg transition font-medium">签到</button>
      <p id="checkin-info" class="text-xs text-gray-500 mt-2">-</p>
    </div>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <!-- 左侧：充值 + 订单 -->
    <div class="space-y-4">
      <!-- 充值面板 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <h2 class="text-sm font-semibold text-gray-300 mb-3">积分充值</h2>
        <div id="recharge-panel">
          <div class="flex gap-2 mb-3">
            <input id="recharge-money" type="number" min="1" max="10000" placeholder="充值金额（元）" class="flex-1 bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm focus:border-blue-500 outline-none">
            <button onclick="doRecharge()" class="bg-blue-600 hover:bg-blue-700 text-white text-sm px-4 py-2 rounded transition font-medium">充值</button>
          </div>
          <p class="text-xs text-gray-500">1 元 = 1 积分，最低 1 元</p>
          <p id="recharge-msg" class="text-xs mt-2 hidden"></p>
        </div>
        <div id="recharge-unavailable" class="hidden">
          <p class="text-xs text-gray-500">充值功能未配置</p>
        </div>
      </div>

      <!-- 订单记录 -->
      <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-gray-300">订单记录</h2>
          <span class="text-xs text-gray-500" id="order-total">共 0 条</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-xs">
            <thead><tr class="text-gray-400 border-b border-gray-700"><th class="text-left py-2 px-2">订单号</th><th class="text-left py-2 px-2">金额</th><th class="text-left py-2 px-2">积分</th><th class="text-left py-2 px-2">状态</th><th class="text-left py-2 px-2">时间</th></tr></thead>
            <tbody id="order-tbody"></tbody>
          </table>
        </div>
        <div class="flex items-center justify-between mt-2">
          <button onclick="orderPrev()" id="order-btn-prev" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 transition" disabled>上一页</button>
          <span id="order-page-info" class="text-xs text-gray-500">1 / 1</span>
          <button onclick="orderNext()" id="order-btn-next" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 transition" disabled>下一页</button>
        </div>
      </div>
    </div>

    <!-- 右侧：积分明细 -->
    <div class="bg-gray-900 border border-gray-700 rounded-lg p-4">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-sm font-semibold text-gray-300">积分明细</h2>
        <span class="text-xs text-gray-500" id="log-total">共 0 条</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead><tr class="text-gray-400 border-b border-gray-700"><th class="text-left py-2 px-2">时间</th><th class="text-left py-2 px-2">类型</th><th class="text-left py-2 px-2">金额</th><th class="text-left py-2 px-2">余额</th><th class="text-left py-2 px-2">说明</th></tr></thead>
          <tbody id="log-tbody"></tbody>
        </table>
      </div>
      <div class="flex items-center justify-between mt-2">
        <button onclick="logPrev()" id="log-btn-prev" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 transition" disabled>上一页</button>
        <span id="log-page-info" class="text-xs text-gray-500">1 / 1</span>
        <button onclick="logNext()" id="log-btn-next" class="text-xs bg-gray-800 hover:bg-gray-700 px-3 py-1 rounded disabled:opacity-30 transition" disabled>下一页</button>
      </div>
    </div>
  </div>

  <!-- API 使用教程 -->
  <div class="mt-6 bg-gray-900 border border-gray-700 rounded-lg">
    <button onclick="this.nextElementSibling.classList.toggle('hidden');this.querySelector('span:last-child').textContent=this.nextElementSibling.classList.contains('hidden')?'▶':'▼'" class="w-full flex items-center justify-between p-4 text-left">
      <span class="text-sm font-semibold text-gray-300">API 使用教程</span>
      <span class="text-gray-500 text-xs">▶</span>
    </button>
    <div class="hidden px-4 pb-4">
      <div class="space-y-4 text-sm text-gray-300">
        <div>
          <h3 class="font-medium text-blue-400 mb-2">认证方式</h3>
          <p class="mb-1">所有 API 请求需要使用 API Key 认证，支持两种方式：</p>
          <ul class="list-disc pl-6 space-y-1 text-gray-400 text-xs">
            <li>Header: <code class="bg-gray-800 px-1 rounded">Authorization: Bearer ts_xxx</code></li>
            <li>Query: <code class="bg-gray-800 px-1 rounded">?key=ts_xxx</code></li>
          </ul>
        </div>
        <div>
          <h3 class="font-medium text-blue-400 mb-2">创建任务</h3>
          <p class="mb-1">向 <code class="bg-gray-800 px-1.5 py-0.5 rounded text-blue-300">/turnstile</code> 发送 GET 请求：</p>
          <div class="bg-gray-800 rounded p-3 text-xs font-mono text-gray-300 overflow-x-auto">GET /turnstile?url=https://example.com&amp;sitekey=YOUR_SITEKEY&amp;key=ts_xxx</div>
          <p class="text-xs text-gray-500 mt-1">参数：url（目标网址）、sitekey（站点密钥）、action（可选）、cdata（可选）</p>
        </div>
        <div>
          <h3 class="font-medium text-blue-400 mb-2">查询结果</h3>
          <p class="mb-1">向 <code class="bg-gray-800 px-1.5 py-0.5 rounded text-blue-300">/result</code> 发送 GET 请求：</p>
          <div class="bg-gray-800 rounded p-3 text-xs font-mono text-gray-300 overflow-x-auto">GET /result?id=TASK_ID&amp;key=ts_xxx</div>
          <p class="text-xs text-gray-500 mt-1">返回 status: "processing" 表示处理中，errorId: 0 + solution.token 表示成功</p>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let logPage=1,logTotal=1,orderPage=1,orderTotal=1;
const TYPE_MAP={initial:'注册赠送',checkin:'签到',recharge:'充值',consume:'消耗',refund:'退款',admin_adjust:'管理员调整'};
const STATUS_MAP={pending:'待支付',paid:'已支付',failed:'失败',refunded:'已退款'};

function escapeHtml(v){
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function api(path,opts){const r=await fetch(path,opts);return r.json()}

async function loadCredits(){
  try{
    const d=await api('/api/user/credits');
    document.getElementById('credit-balance').textContent=d.credits.balance;
    document.getElementById('credit-earned').textContent=d.credits.total_earned;
    document.getElementById('credit-spent').textContent=d.credits.total_spent;
    const btn=document.getElementById('btn-checkin');
    const info=document.getElementById('checkin-info');
    if(d.checkin.checked_today){btn.disabled=true;btn.textContent='已签到';}
    info.textContent='连续签到 '+d.checkin.streak+' 天';
  }catch(e){console.error('loadCredits',e)}
}

async function doCheckin(){
  const btn=document.getElementById('btn-checkin');
  btn.disabled=true;btn.textContent='签到中...';
  try{
    const r=await fetch('/api/user/checkin',{method:'POST'});
    const d=await r.json();
    if(r.ok){
      btn.textContent='已签到';
      alert('签到成功！获得 '+d.credits_earned+' 积分');
      loadCredits();loadLog();
    }else{
      btn.textContent='已签到';
    }
  }catch(e){btn.disabled=false;btn.textContent='签到';console.error(e)}
}

async function doRecharge(){
  const money=document.getElementById('recharge-money').value;
  const msg=document.getElementById('recharge-msg');
  if(!money||money<1){msg.textContent='请输入有效金额';msg.className='text-xs mt-2 text-red-400';msg.classList.remove('hidden');return;}
  try{
    const r=await fetch('/api/user/recharge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({money:parseFloat(money)})});
    const d=await r.json();
    if(r.ok&&d.pay_url){
      window.open(d.pay_url,'_blank');
      msg.textContent='已跳转支付页面，支付完成后请刷新';msg.className='text-xs mt-2 text-green-400';msg.classList.remove('hidden');
      setTimeout(()=>{loadOrders();loadCredits();},5000);
    }else{
      msg.textContent=d.error||'创建订单失败';msg.className='text-xs mt-2 text-red-400';msg.classList.remove('hidden');
    }
  }catch(e){msg.textContent='网络错误';msg.className='text-xs mt-2 text-red-400';msg.classList.remove('hidden');}
}

async function loadLog(){
  try{
    const d=await api('/api/user/credit-log?page='+logPage+'&per_page=15');
    logTotal=d.total_pages;
    document.getElementById('log-total').textContent='共 '+d.total+' 条';
    document.getElementById('log-page-info').textContent=d.page+' / '+d.total_pages;
    document.getElementById('log-btn-prev').disabled=(d.page<=1);
    document.getElementById('log-btn-next').disabled=(d.page>=d.total_pages);
    const tbody=document.getElementById('log-tbody');
    tbody.innerHTML='';
    if(d.items.length===0){tbody.innerHTML='<tr><td colspan="5" class="text-center py-4 text-gray-600">暂无记录</td></tr>';return;}
    d.items.forEach(i=>{
      const cls=i.amount>=0?'text-green-400':'text-red-400';
      const sign=i.amount>=0?'+':'';
      const desc=i.description||'';
      const descText=desc?desc:'-';
      const tr=document.createElement('tr');
      tr.className='border-b border-gray-800';
      tr.innerHTML='<td class="py-1.5 px-2 text-gray-500">'+escapeHtml(i.created_at||'-')+'</td><td class="py-1.5 px-2">'+escapeHtml((TYPE_MAP[i.type]||i.type))+'</td><td class="py-1.5 px-2 '+cls+'">'+escapeHtml(sign+i.amount)+'</td><td class="py-1.5 px-2">'+escapeHtml(i.balance_after)+'</td><td class="py-1.5 px-2 text-gray-500 truncate max-w-[120px]" title="'+escapeHtml(desc)+'">'+escapeHtml(descText)+'</td>';
      tbody.appendChild(tr);
    });
  }catch(e){console.error('loadLog',e)}
}
function logPrev(){if(logPage>1){logPage--;loadLog()}}
function logNext(){if(logPage<logTotal){logPage++;loadLog()}}

async function loadOrders(){
  try{
    const d=await api('/api/user/orders?page='+orderPage+'&per_page=10');
    orderTotal=d.total_pages;
    document.getElementById('order-total').textContent='共 '+d.total+' 条';
    document.getElementById('order-page-info').textContent=d.page+' / '+d.total_pages;
    document.getElementById('order-btn-prev').disabled=(d.page<=1);
    document.getElementById('order-btn-next').disabled=(d.page>=d.total_pages);
    const tbody=document.getElementById('order-tbody');
    tbody.innerHTML='';
    if(d.items.length===0){tbody.innerHTML='<tr><td colspan="5" class="text-center py-4 text-gray-600">暂无订单</td></tr>';return;}
    d.items.forEach(o=>{
      const scls=o.status==='paid'?'text-green-400':(o.status==='pending'?'text-yellow-400':'text-red-400');
      const tradeNo=String(o.out_trade_no||'');
      const tradeNoShort=tradeNo.substring(0,16)+'…';
      const tr=document.createElement('tr');
      tr.className='border-b border-gray-800';
      tr.innerHTML='<td class="py-1.5 px-2 font-mono text-gray-400 text-[10px]" title="'+escapeHtml(tradeNo)+'">'+escapeHtml(tradeNoShort)+'</td><td class="py-1.5 px-2">'+escapeHtml(o.money)+'元</td><td class="py-1.5 px-2">'+escapeHtml(o.amount)+'</td><td class="py-1.5 px-2 '+scls+'">'+escapeHtml((STATUS_MAP[o.status]||o.status))+'</td><td class="py-1.5 px-2 text-gray-500">'+escapeHtml(o.created_at||'-')+'</td>';
      tbody.appendChild(tr);
    });
  }catch(e){console.error('loadOrders',e)}
}
function orderPrev(){if(orderPage>1){orderPage--;loadOrders()}}
function orderNext(){if(orderPage<orderTotal){orderPage++;loadOrders()}}

// 检查充值是否可用
fetch('/api/user/recharge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({money:0})}).then(r=>{
  if(r.status===503){
    document.getElementById('recharge-panel').classList.add('hidden');
    document.getElementById('recharge-unavailable').classList.remove('hidden');
  }
}).catch(()=>{});

loadCredits();loadLog();loadOrders();
</script>
</body>
</html>"""
        username = session.get("username", "")
        safe_username = html.escape(str(username), quote=True)
        return self._dashboard_template.replace("__USERNAME__", safe_username)


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Turnstile API Server")

    parser.add_argument('--no-headless', action='store_true', help='Run the browser with GUI (disable headless mode). By default, headless mode is enabled.')
    parser.add_argument('--useragent', type=str, help='User-Agent string (if not specified, random configuration is used)')
    parser.add_argument('--debug', action='store_true', help='Enable or disable debug mode for additional logging and troubleshooting information (default: False)')
    parser.add_argument('--browser_type', type=str, default='chromium', help='Specify the browser type for the solver. Supported options: chromium, chrome, msedge, camoufox (default: chromium)')
    parser.add_argument('--thread', type=int, default=1, help='Set the number of browser threads to use for multi-threaded mode. Increasing this will speed up execution but requires more resources (default: 1)')
    parser.add_argument('--proxy', action='store_true', help='Enable proxy support for the solver (Default: False)')
    parser.add_argument('--random', action='store_true', help='Use random User-Agent and Sec-CH-UA configuration from pool')
    parser.add_argument('--browser', type=str, help='Specify browser name to use (e.g., chrome, firefox)')
    parser.add_argument('--version', type=str, help='Specify browser version to use (e.g., 139, 141)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Specify the IP address where the API solver runs. (Default: 127.0.0.1)')
    parser.add_argument('--port', type=str, default='5072', help='Set the port for the API solver to listen on. (Default: 5072)')
    return parser.parse_args()


def create_app(headless: bool, useragent: str, debug: bool, browser_type: str, thread: int, proxy_support: bool, use_random_config: bool, browser_name: str, browser_version: str) -> Quart:
    server = TurnstileAPIServer(headless=headless, useragent=useragent, debug=debug, browser_type=browser_type, thread=thread, proxy_support=proxy_support, use_random_config=use_random_config, browser_name=browser_name, browser_version=browser_version)
    server.app.server = server
    return server.app


if __name__ == '__main__':
    args = parse_args()

    if not os.environ.get("ADMIN_PASSWORD"):
        logger.error("必须设置 ADMIN_PASSWORD 环境变量")
        sys.exit(1)

    browser_types = [
        'chromium',
        'chrome',
        'msedge',
        'camoufox',
    ]
    if args.browser_type not in browser_types:
        logger.error(f"Unknown browser type: {COLORS.get('RED')}{args.browser_type}{COLORS.get('RESET')} Available browser types: {browser_types}")
    else:
        app = create_app(
            headless=not args.no_headless, 
            debug=args.debug, 
            useragent=args.useragent, 
            browser_type=args.browser_type, 
            thread=args.thread, 
            proxy_support=args.proxy,
            use_random_config=args.random,
            browser_name=args.browser,
            browser_version=args.version
        )
        app.run(host=args.host, port=int(args.port))
