from flask import Flask, request, Response
import time
from winnie_db import init_db, insert

app = Flask(__name__)

# Initialize DB when app starts
init_db()

@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def catch_all(path):
    data = {
        "timestamp": int(time.time()),
        "src_ip": request.remote_addr or "unknown",
        "method": request.method,
        "path": "/" + path,
        "headers": str(dict(request.headers)),
        "body": (request.get_data() or b"").decode('utf-8', errors='replace')
    }
    insert("http_requests", data)
    print(f"[HTTP] {data['src_ip']} {data['method']} {data['path']}")
    return Response("<html><body><h1>It works.</h1></body></html>", status=200, mimetype='text/html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
