from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import qrcode
from io import BytesIO
from datetime import datetime
import os

app = Flask(__name__)

# Kunci enkripsi (gunakan key derivation untuk keamanan tambahan)
PASSWORD = "super_secure_password"
SALT = b"this_is_a_fixed_salt"  # Panjang 16 byte

TMP_DIR = '/tmp'
SALT_FILE = os.path.join(TMP_DIR, "salt.bin")

# Pastikan SALT disimpan atau dimuat
def get_or_create_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt

# Gunakan fungsi ini untuk mendapatkan SALT
SALT = get_or_create_salt()

# Fungsi untuk menghasilkan kunci AES
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

SECRET_KEY = generate_key(PASSWORD, SALT)

# Konfigurasi Database
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(TMP_DIR, "tiket_konser.db")

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Model Database
class Tiket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    no_hp = db.Column(db.String(15), nullable=False)
    tempat_duduk = db.Column(db.String(10), nullable=False)
    jumlah_tiket = db.Column(db.Integer, nullable=False)
    id_tiket = db.Column(db.String(50), unique=True, nullable=False)
    tanggal_pesan = db.Column(db.DateTime, default=datetime.utcnow)
    qr_code = db.Column(db.Text, nullable=False)

# Fungsi enkripsi dan dekripsi
def encrypt_data(data):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + encryptor.tag + ciphertext).decode()

def decrypt_data(data):
    raw_data = base64.b64decode(data)
    nonce = raw_data[:12]
    tag = raw_data[12:28]
    ciphertext = raw_data[28:]
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Fungsi untuk membuat ID tiket dengan format khusus
def generate_ticket_id():
    urutan = Tiket.query.count() + 1
    tanggal = datetime.now().strftime('%Y%m%d')
    return f"TKT{urutan:04d}{tanggal}"

# Route untuk halaman utama
@app.route('/')
def home():
    return render_template('flowchart.html')

# Route untuk halaman tiket
@app.route('/index')
def index():
    return render_template('index.html')

# Route untuk generate QR code
@app.route('/generate', methods=['POST'])
def generate_qr():
    try:
        # Ambil data dari form
        nama = request.form.get('nama', '').strip()
        email = request.form.get('email', '').strip()
        no_hp = request.form.get('no_hp', '').strip()
        tempat_duduk = request.form.get('tempat_duduk', '').strip()
        jumlah_tiket = int(request.form.get('jumlah_tiket', '1'))

        if not nama or not email or not no_hp or not tempat_duduk or jumlah_tiket < 1:
            return jsonify({'status': 'error', 'message': 'Semua field harus diisi dengan benar'}), 400

        tiket_list = []
        for i in range(1, jumlah_tiket + 1):
            # Generate ID Tiket
            id_tiket = generate_ticket_id()

            # Enkripsi ID Tiket
            encrypted_data = encrypt_data(id_tiket)

            # Generate QR Code
            qr = qrcode.QRCode(box_size=7, border=0)
            qr.add_data(encrypted_data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

            # Simpan ke Database
            tiket = Tiket(
                nama=nama,
                email=email,
                no_hp=no_hp,
                tempat_duduk=tempat_duduk,
                jumlah_tiket=1,
                id_tiket=id_tiket,
                qr_code=qr_base64
            )
            db.session.add(tiket)
            tiket_list.append({
                'id_tiket': id_tiket,
                'ciphertext': encrypted_data,
                'qr_image': qr_base64
            })
        db.session.commit()

        return jsonify({'status': 'success', 'tickets': tiket_list})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Route untuk decrypt QR code
@app.route('/decrypt', methods=['POST'])
def decrypt_qr():
    encrypted_data = request.form.get('encrypted_data', '').strip()

    if not encrypted_data:
        return jsonify({'status': 'error', 'message': 'Data terenkripsi tidak boleh kosong'}), 400

    try:
        decrypted_data = decrypt_data(encrypted_data).decode()
        tiket = Tiket.query.filter_by(id_tiket=decrypted_data).first()

        if not tiket:
            # Jika tiket tidak ditemukan, kembalikan error
            return jsonify({'status': 'error', 'message': 'Data chiper tidak valid atau tiket tidak ditemukan'}), 404

        return jsonify({
            'status': 'success',
            'ciphertext': encrypted_data,
            'decrypted_data': decrypted_data,
            'ticket_data': {
                'nama': tiket.nama,
                'email': tiket.email,
                'no_hp': tiket.no_hp,
                'tempat_duduk': tiket.tempat_duduk,
                'tanggal_pesan': tiket.tanggal_pesan.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        # Jika ada kesalahan dalam proses dekripsi
        print(f"Error decrypting data: {e}")
        return jsonify({'status': 'error', 'message': 'Dekripsi gagal atau data tidak valid', 'barcode_content': encrypted_data}), 400


# Pastikan database dan tabel selalu tersedia
def ensure_database():
    if not os.path.exists(DB_PATH):  # Periksa apakah file database ada
        os.makedirs(TMP_DIR, exist_ok=True)  # Buat direktori jika belum ada
    with app.app_context():
        inspector = db.inspect(db.engine)
        if not inspector.has_table("tiket"):  # Periksa apakah tabel "tiket" ada
            db.create_all()
            print(f"Database and table created at: {DB_PATH}")

# Panggil fungsi untuk memastikan database dan tabel dibuat
ensure_database()

if __name__ == '__main__':
    app.run(debug=False)