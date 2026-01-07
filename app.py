# ===============================
# 1. IMPORT LENGKAP
# ===============================
import os
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from sqlalchemy import or_ 

# Import Modul Kripto Buatan Sendiri
from crypto.super_enk import encrypt_message, decrypt_message

# ===============================
# 2. KONFIGURASI APP
# ===============================
app = Flask(__name__)
app.secret_key = "rahasia_negara_api" 

# Konfigurasi Upload Folder
UPLOAD_FOLDER = 'static/uploads'
# Gunakan path absolut untuk folder upload agar aman
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ABS_UPLOAD_FOLDER = os.path.join(BASE_DIR, UPLOAD_FOLDER)

if not os.path.exists(ABS_UPLOAD_FOLDER):
    os.makedirs(ABS_UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # Path relatif untuk DB
app.config['ABS_UPLOAD_FOLDER'] = ABS_UPLOAD_FOLDER # Path absolut untuk simpan file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securetalk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
SUPER_KEY = "kunci_rahasia_kelompok" 

# ===============================
# 3. MODEL DATABASE
# ===============================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class Chat(db.Model):
    __tablename__ = 'chats'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) 
    cipher_text = db.Column(db.Text, nullable=False)
    is_stego = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FileModel(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    filename = db.Column(db.String(200))
    encrypted_path = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ===============================
# 4. ROUTE APLIKASI
# ===============================
@app.route("/")
def home():
    if "user_id" in session: return redirect("/dashboard")
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            return "Username sudah ada!"
        
        hashed = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed)
        db.session.add(new_user)
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
        return "Login Gagal"
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session: return redirect("/login")
    return render_template("dashboard.html")

# --- FITUR UTAMA: CHAT ---
@app.route("/chat", methods=["GET", "POST"])
def chat():
    if "user_id" not in session: return redirect("/login")
    current_user_id = session["user_id"]

    # --- 1. PROSES KIRIM PESAN (POST) ---
    if request.method == "POST":
        try:
            receiver_input = request.form.get("receiver_id")
            message = request.form.get("message", "")
            image_file = request.files.get("image")

            final_receiver_id = None
            if receiver_input and receiver_input != "0":
                final_receiver_id = int(receiver_input)

            cipher_text = encrypt_message(SUPER_KEY, message)
            is_stego_flag = False

            if image_file and image_file.filename != '':
                filename = secure_filename(image_file.filename)
                
                # Gunakan path absolut untuk penyimpanan
                temp_filename = "temp_" + filename
                temp_path = os.path.join(app.config['ABS_UPLOAD_FOLDER'], temp_filename)
                
                stego_name = "stego_" + str(int(datetime.now().timestamp())) + "_" + filename
                stego_path = os.path.join(app.config['ABS_UPLOAD_FOLDER'], stego_name)
                
                image_file.save(temp_path)
                
                from crypto import steganography as stego
                # Encode gambar
                if stego.encode_image(temp_path, cipher_text, stego_path):
                    # Simpan PATH RELATIF ke database (agar bisa diload HTML)
                    cipher_text = f"static/uploads/{stego_name}" 
                    is_stego_flag = True
                else:
                    print("Gagal Encode Stegano")
                
                if os.path.exists(temp_path): os.remove(temp_path)

            new_chat = Chat(
                sender_id=current_user_id,
                receiver_id=final_receiver_id,
                cipher_text=cipher_text,
                is_stego=is_stego_flag
            )
            db.session.add(new_chat)
            db.session.commit()
            return redirect("/chat")

        except Exception as e:
            print(f"Error Chat POST: {e}")
            return "Terjadi kesalahan saat mengirim pesan."

    # --- 2. TAMPILKAN DATA (GET) ---
    all_users = User.query.filter(User.id != current_user_id).all()

    chats = Chat.query.filter(
        or_(
            Chat.sender_id == current_user_id,
            Chat.receiver_id == current_user_id,
            Chat.receiver_id == None 
        )
    ).order_by(Chat.created_at).all()

    processed_chats = []
    for c in chats:
        display_text = ""
        image_url = None
        
        sender_obj = User.query.get(c.sender_id)
        sender_name = sender_obj.username if sender_obj else "Unknown"

        try:
            if c.is_stego:
                # 1. Ambil path relatif dari DB (misal: static/uploads/foto.png)
                db_path_rel = c.cipher_text.replace("\\", "/")
                image_url = db_path_rel

                # 2. Buat ABSOLUTE PATH untuk proses decode (SOLUSI ERROR)
                # app.root_path adalah folder dimana app.py berada
                full_path_abs = os.path.join(app.root_path, db_path_rel)

                try:
                    from crypto import steganography as stego
                    # Cek apakah file benar-benar ada sebelum decode
                    if os.path.exists(full_path_abs):
                        extracted = stego.decode_image(full_path_abs)
                        if extracted:
                            display_text = decrypt_message(SUPER_KEY, extracted)
                        else:
                            display_text = "[Gagal Ekstrak / Gambar Rusak]"
                    else:
                        display_text = "[File Gambar Tidak Ditemukan]"
                except Exception as e:
                    print(f"DEBUG ERROR: {e}") # Cek terminal jika masih error
                    display_text = "[Error Baca Gambar]"
            else:
                display_text = decrypt_message(SUPER_KEY, c.cipher_text)
        except:
            display_text = "[Gagal Dekripsi]"

        processed_chats.append({
            'id': c.id,
            'sender_id': c.sender_id,
            'sender_name': sender_name,
            'receiver_id': c.receiver_id,
            'message': display_text,
            'created_at': c.created_at,
            'image_url': image_url
        })

    return render_template("chat.html", chats=processed_chats, users=all_users)

# --- FITUR TAMBAHAN: STORAGE (FILE) ---
@app.route("/storage", methods=["GET", "POST"])
def storage():
    if "user_id" not in session: return redirect("/login")
    if request.method == "POST":
        f = request.files['file']
        if f:
            fname = secure_filename(f.filename)
            enc_content = encrypt_message(SUPER_KEY, f.read().hex()).encode()
            
            # Gunakan ABS_UPLOAD_FOLDER
            save_path = os.path.join(app.config['ABS_UPLOAD_FOLDER'], f"{session['user_id']}_{fname}.enc")
            with open(save_path, "wb") as file_out:
                file_out.write(enc_content)
            
            db.session.add(FileModel(user_id=session['user_id'], filename=fname, encrypted_path=save_path))
            db.session.commit()
    
    files = FileModel.query.filter_by(user_id=session['user_id']).all()
    return render_template("storage.html", files=files)

@app.route("/download/<int:fid>")
def download(fid):
    f_rec = FileModel.query.get_or_404(fid)
    if f_rec.user_id != session['user_id']: return "Unauthorized"
    
    # Pastikan file ada sebelum dibaca
    if not os.path.exists(f_rec.encrypted_path):
        return "File fisik tidak ditemukan di server."

    with open(f_rec.encrypted_path, "rb") as f:
        enc_data = f.read().decode()
    dec_hex = decrypt_message(SUPER_KEY, enc_data)
    return send_file(io.BytesIO(bytes.fromhex(dec_hex)), download_name=f_rec.filename, as_attachment=True)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)