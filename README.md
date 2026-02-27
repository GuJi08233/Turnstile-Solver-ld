# Cloudflare Turnstile 验证码求解器

基于 Python 的 Turnstile 验证码求解工具，使用 patchright 和 camoufox 库，支持多线程执行、API 集成和多种浏览器。能够快速高效地求解验证码，支持自定义配置和详细日志记录。

## 功能特点

- **多线程执行** - 同时求解多个验证码
- **多浏览器支持** - Chromium、Chrome、Edge 和 Camoufox
- **代理支持** - 从 proxies.txt 文件中使用代理
- **随机浏览器配置** - 轮换 User-Agent 和 Sec-CH-UA 头信息
- **详细日志** - 完整的调试信息
- **REST API** - 方便与其他应用集成
- **数据库存储** - SQLite 数据库持久化存储结果
- **自动清理** - 自动清理过期结果
- **资源优化** - 阻止不必要的资源加载以提升性能

## 浏览器配置

求解器支持多种浏览器配置，包含真实的 User-Agent 和 Sec-CH-UA 头信息：

- **Chrome**（版本 136-139）
- **Edge**（版本 137-139）
- **Avast**（版本 137-138）
- **Brave**（版本 137-139）

### 代理格式

在 `proxies.txt` 中按以下格式添加代理：

```
ip:port
ip:port:username:password
scheme://ip:port
scheme://username:password@ip:port
```

## 安装说明

确保系统已安装 Python 3.8+。

### 1. 创建 Python 虚拟环境：

```bash
python -m venv venv
```

### 2. 激活虚拟环境：

**Windows:**
```bash
venv\Scripts\activate
```

**macOS/Linux:**
```bash
source venv/bin/activate
```

### 3. 安装依赖：

```bash
pip install -r requirements.txt
```

### 4. 选择并安装浏览器：

可以选择 Chromium、Chrome、Edge 或 Camoufox：

**安装 Chromium:**
```bash
python -m patchright install chromium
```

**安装 Chrome:**
- macOS/Windows: 下载安装 Chrome 浏览器
- Linux (Debian/Ubuntu):
```bash
apt update
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install -y ./google-chrome-stable_current_amd64.deb
apt -f install -y
rm ./google-chrome-stable_current_amd64.deb
```

**安装 Edge:**
```bash
python -m patchright install msedge
```

**安装 Camoufox:**
```bash
python -m camoufox fetch
```

### 5. 启动运行：

```bash
python api_solver.py
```

## 命令行参数

| 参数 | 默认值 | 类型 | 说明 |
|------|--------|------|------|
| `--no-headless` | False | 布尔值 | 以 GUI 模式运行浏览器（禁用无头模式） |
| `--useragent` | None | 字符串 | 自定义 User-Agent（使用 camoufox 时无需设置） |
| `--debug` | False | 布尔值 | 启用调试模式，输出额外的日志信息 |
| `--browser_type` | chromium | 字符串 | 浏览器类型：chromium、chrome、msedge、camoufox |
| `--thread` | 4 | 整数 | 浏览器线程数 |
| `--host` | 0.0.0.0 | 字符串 | API 服务监听地址 |
| `--port` | 5072 | 整数 | API 服务监听端口 |
| `--proxy` | False | 布尔值 | 从 proxies.txt 随机选择代理 |
| `--random` | False | 布尔值 | 使用随机的 User-Agent 和 Sec-CH-UA 配置 |
| `--browser` | None | 字符串 | 指定浏览器名称（如 chrome、firefox） |
| `--version` | None | 字符串 | 指定浏览器版本（如 139、141） |

## API 文档

### 求解验证码

```
GET /turnstile?url=https://example.com&sitekey=0x4AAAAAAA
```

**请求参数：**

| 参数 | 类型 | 说明 | 必填 |
|------|------|------|------|
| `url` | 字符串 | 包含验证码的目标网址 | 是 |
| `sitekey` | 字符串 | 验证码站点密钥 | 是 |
| `action` | 字符串 | 验证码求解时触发的动作，如 login | 否 |
| `cdata` | 字符串 | 自定义数据参数 | 否 |

**响应示例：**

请求成功后返回任务 ID：

```json
{
  "task_id": "d2cbb257-9c37-4f9c-9bc7-1eaee72d96a8"
}
```

### 获取结果

```
GET /result?id=f0dbe75b-fa76-41ad-89aa-4d3a392040af
```

**请求参数：**

| 参数 | 类型 | 说明 | 必填 |
|------|------|------|------|
| `id` | 字符串 | /turnstile 返回的任务 ID | 是 |

**响应示例：**

求解成功：

```json
{
  "status": "ready",
  "value": "0.KBtT-r",
  "elapsed_time": 7.625
}
```

处理中：

```json
{
  "status": "processing"
}
```

求解失败：

```json
{
  "status": "fail",
  "value": "CAPTCHA_FAIL",
  "elapsed_time": 30.0
}
```

## 常见问题

1. **找不到浏览器**：请按安装说明正确安装所需浏览器
2. **权限不足**：使用适当权限运行或检查文件权限
3. **端口被占用**：使用 `--port` 参数更换端口
4. **代理连接失败**：检查代理格式和可用性

### 调试模式

启用调试模式获取详细日志：

```bash
python api_solver.py --debug
```

## 性能指标

- **平均求解时间**：5-15 秒
- **成功率**：95%+（取决于站点复杂度）
- **内存占用**：每个浏览器线程约 50-100MB
- **CPU 占用**：中等（取决于线程数）

## 许可声明

本项目仅供学习和研究用途，使用风险自负。
