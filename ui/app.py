from flask import Flask, jsonify

app = Flask(__name__)
state_provider = None  # injected later

@app.route("/api/status")
def status():
    if state_provider:
        return jsonify(state_provider())
    return jsonify({})

def start_ui(get_state_func):
    global state_provider
    state_provider = get_state_func
    app.run(port=5000)
