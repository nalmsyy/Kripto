from flask import Flask

app = Flask(__name__)
app.secret_key = "securetalk-secret-key"

@app.route("/")
def home():
    return "SecureTalk is running"

if __name__ == "__main__":
    app.run(debug=True, port=8080)
