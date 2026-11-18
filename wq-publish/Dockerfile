FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WQ_DATA_DIR=/data \
    WQ_DOWNSTREAM_DIR=/downstream

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY wq_publish ./wq_publish
COPY wsgi.py serve.py ./

# 以非 root 运行；数据卷的属主由镜像内目录初始化
RUN useradd --create-home --uid 10001 wq \
    && mkdir -p /data /downstream \
    && chown -R wq:wq /data /downstream /app
USER wq

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/evidence', timeout=3)"

CMD ["python", "serve.py"]
