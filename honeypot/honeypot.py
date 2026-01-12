from flask import Flask, request
import datetime

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def fake_login():
    if request.method == "POST":
        with open("dataset/honeypot.log", "a") as f:
            f.write(f"{datetime.datetime.now()} | "
                    f"IP:{request.remote_addr} | "
                    f"USER:{request.form.get('username')} | "
                    f"PASS:{request.form.get('password')}\n")
        return "Invalid credentials"

    return """
    <h2>Smart Camera Login</h2>
    <form method="post">
        <input name="username" placeholder="admin"><br>
        <input name="password" type="password"><br>
        <button>Login</button>
    </form>
    """

def start_honeypot():
    app.run(host="0.0.0.0", port=8080)
