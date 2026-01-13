from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def fake_login():
    ip = request.remote_addr
    print(f"[HONEYPOT] Connection from {ip}")

    if request.method == "POST":
        user = request.form.get("username")
        pwd = request.form.get("password")
        print(f"[HONEYPOT] Credentials captured -> {user}:{pwd}")

    return """
    <html>
    <head><title>Smart Camera Login</title></head>
    <body style="font-family:Arial">
        <h3>IoT Camera Login</h3>
        <form method="POST">
            <input name="username" placeholder="admin"/><br><br>
            <input name="password" type="password"/><br><br>
            <button>Login</button>
        </form>
    </body>
    </html>
    """

app.run(host="0.0.0.0", port=8080)
