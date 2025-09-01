from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
from winnie_db import fetch_recent
import uvicorn
import csv
import io

app = FastAPI()

@app.get("/")
def ui():
    html = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>WinnieThePooh - Dashboard</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        button { margin-right: 10px; padding: 6px 12px; }
        table { border-collapse: collapse; margin-top: 20px; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; }
        th { background-color: #f4f4f4; }
      </style>
    </head>
    <body>
      <h1>🐻 WinnieThePooh Honeypot Dashboard</h1>
      <div>
        <button onclick="load('ssh')">Load SSH Attempts</button>
        <button onclick="load('http')">Load HTTP Requests</button>
        <button onclick="download('ssh')">Download SSH CSV</button>
      </div>
      <div id="content"><p>Loading...</p></div>

      <script>
        async function load(kind){
          const res = await fetch('/api/' + kind + '?limit=50');
          const arr = await res.json();
          let html = '<table><thead>';
          if(arr.length > 0){
            html += '<tr>' + Object.keys(arr[0]).map(k => '<th>'+k+'</th>').join('') + '</tr></thead><tbody>';
            for(const r of arr){
              html += '<tr>' + Object.values(r).map(v => '<td>'+String(v).replace(/</g,'&lt;')+'</td>').join('') + '</tr>';
            }
            html += '</tbody></table>';
          } else {
            html = '<p>No data available</p>';
          }
          document.getElementById('content').innerHTML = html;
        }

        function download(kind){
          window.location = '/api/' + kind + '/csv';
        }

        // Initial load
        load('ssh');
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/api/ssh")
def api_ssh(limit: int = 100):
    rows = fetch_recent("ssh_attempts", limit)
    return rows

@app.get("/api/http")
def api_http(limit: int = 100):
    rows = fetch_recent("http_requests", limit)
    return rows

@app.get("/api/ssh/csv")
def api_ssh_csv(limit: int = 100):
    rows = fetch_recent("ssh_attempts", limit)
    if not rows:
        return Response(content="No data", media_type="text/plain")
    si = io.StringIO()
    cw = csv.DictWriter(si, fieldnames=rows[0].keys())
    cw.writeheader()
    cw.writerows(rows)
    return Response(
        content=si.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ssh_attempts.csv"}
    )

if __name__ == "__main__":
    uvicorn.run("dashboard:app", host="10.239.111.151", port=8000, reload=True)
