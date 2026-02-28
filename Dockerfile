FROM python:3.11-slim

WORKDIR /app

# Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装 Chromium 及其全部系统依赖（--with-deps 自动安装 libcups2 等）
RUN python -m patchright install --with-deps chromium

# 复制项目文件
COPY *.py ./

# 数据持久化目录
RUN mkdir -p /app/data
VOLUME /app/data

# 环境变量默认值
ENV DB_PATH=/app/data/results.db

EXPOSE 5072

ENTRYPOINT ["python", "api_solver.py"]
CMD ["--host", "0.0.0.0", "--port", "5072"]
