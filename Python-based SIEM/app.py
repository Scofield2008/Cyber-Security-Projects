from flask import Flask, render_template
from monitor import start_monitoring, alerts

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("dashboard.html", alerts=alerts)

if __name__ == "__main__":
    start_monitoring()
    app.run(debug=True)
