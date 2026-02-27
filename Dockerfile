FROM python:3.11-slim

# 系统依赖 (Chromium 运行所需的共享库)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl fonts-liberation libnss3 libatk-bridge2.0-0 \
    libdrm2 libxcomposite1 libxdamage1 libxrandr2 libgbm1 \
    libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装 Chromium 浏览器
RUN python -m patchright install chromium

# 复制项目文件
COPY *.py .
COPY proxies.txt .

# 数据持久化目录
RUN mkdir -p /app/data
VOLUME /app/data

# 环境变量默认值
ENV DB_PATH=/app/data/results.db

EXPOSE 5072

ENTRYPOINT ["python", "api_solver.py"]
CMD ["--host", "0.0.0.0", "--port", "5072"]
