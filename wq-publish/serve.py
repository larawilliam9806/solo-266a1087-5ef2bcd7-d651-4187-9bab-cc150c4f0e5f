"""Docker Compose 部署入口：单进程多线程等待 HTTP 请求。"""
from waitress import serve

from wq_publish.app import create_app

app = create_app()

if __name__ == "__main__":  # pragma: no cover
    serve(app, host="0.0.0.0", port=5000, threads=8)
