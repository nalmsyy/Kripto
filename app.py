# ===============================
# 1. IMPORT
# ===============================
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from crypto.super_enk import encrypt_message, decrypt_message


# ===============================
# 2. INISIALISASI APP
# ===============================
app = Flask(__name__)
app.secret_key = "securetalk-secret-key"

# ===============================
# 3. KONFIGURASI DATABASE
# ===============================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetalk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===============================
# 4. MODEL DATABASE (DI SINI)
# ===============================
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Chat(db.Model):
    __tablename__ = 'chats'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cipher_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class File(db.Model):
    __tablename__ = 'files'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    encrypted_path = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ===============================
# 5. ROUTE (NANTI DI SINI)
# ===============================
@app.route("/")
def home():
    return "SecureTalk is running"

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # cek username
        if User.query.filter_by(username=username).first():
            return "Username already exists"

        hashed_password = generate_password_hash(password)

        user = User(
            username=username,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()

        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect("/dashboard")
        else:
            return "Login failed"

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")

@app.route("/chat", methods=["GET", "POST"])
def chat():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        message = request.form.get("message")
        image = request.files.get("image")
        receiver_id = int(request.form["receiver_id"])

        if image and message:
            # simpan gambar sementara
            temp_path = f"static/uploads/temp_{image.filename}"
            image.save(temp_path)

            # SUPER ENKRIPSI
            encrypted_msg = encrypt_message(SUPER_KEY, message)

            # STEGANOGRAFI (impor lokal untuk menghindari ImportError saat startup)
            from crypto import steganography as stego
            output_path = f"static/uploads/stego_{image.filename}"
            stego.encode_image(temp_path, encrypted_msg, output_path)

            cipher_text = f"[IMAGE_STEGO]{output_path}"
        else:
            cipher_text = encrypt_message(SUPER_KEY, message)

        chat = Chat(
            sender_id=session["user_id"],
            receiver_id=receiver_id,
            cipher_text=cipher_text
        )
        db.session.add(chat)
        db.session.commit()

        return redirect("/chat")

    chats = Chat.query.all()
    return render_template("chat.html", chats=chats)



@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/storage", methods=["GET", "POST"])
def storage():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files["file"]
        if file:
            raw_data = file.read()
            encrypted_data = encrypt_file(raw_data)

            filename = file.filename
            save_path = f"static/uploads/{session['user_id']}_{filename}.enc"

            with open(save_path, "wb") as f:
                f.write(encrypted_data)

            record = File(
                user_id=session["user_id"],
                filename=filename,
                encrypted_path=save_path
            )
            db.session.add(record)
            db.session.commit()

    files = File.query.filter_by(user_id=session["user_id"]).all()
    return render_template("storage.html", files=files)


# ===============================
# 6. RUN APP & CREATE TABLE
# ===============================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
