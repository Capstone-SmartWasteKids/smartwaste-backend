from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random   
import string
import os
import time
from werkzeug.utils import secure_filename
import numpy as np
from PIL import Image
import tensorflow as tf
import json

# --- 1. Buat Aplikasi Flask ---
app = Flask(__name__) 
# Izinkan Flutter (dari domain lain) untuk mengakses API ini
CORS(app) 

# --- 2. Konfigurasi Database MySQL ---
app.config['MYSQL_HOST'] = '127.0.0.1' 
app.config['MYSQL_PORT'] = 3307
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'smartwaste_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Agar hasilnya berupa JSON

# --- KONFIGURASI EMAIL (GMAIL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'smartwastekids@gmail.com' 
app.config['MAIL_PASSWORD'] = 'ghlq gfai njrm eymm' 
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Konfigurasi untuk upload file
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Path ke model dan label
MODEL_PATH = 'data/model_sampah_mobilenet_final.keras'
LABELS_PATH = 'data/labels.json'

mail = Mail(app)

# Inisialisasi MySQL
mysql = MySQL(app)

# Variabel global untuk model dan label
model = None
class_labels = []

# Fungsi untuk memeriksa ekstensi file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Buat folder upload jika tidak ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def load_model_and_labels():
    """Memuat model Keras dan label dari file JSON."""
    global model, class_labels
    try:
        print("Memuat model Keras...")
        model = tf.keras.models.load_model(MODEL_PATH)
        print("Model berhasil dimuat.")

        print("Memuat label...")
        with open(LABELS_PATH, 'r') as f:
            class_labels = json.load(f)
        print(f"Label berhasil dimuat: {class_labels}")
        
        return True
    except Exception as e:
        print(f"Gagal memuat model atau label: {e}")
        return False

def preprocess_image(image_path, target_size=(128, 128)):
    """
    Melakukan preprocessing pada gambar agar sesuai dengan input model.
    """
    img = Image.open(image_path).convert('RGB')
    img = img.resize(target_size)
    img_array = tf.keras.preprocessing.image.img_to_array(img)
    img_array = np.expand_dims(img_array, axis=0) # Tambah dimensi batch
    img_array /= 255.0 # Normalisasi
    return img_array

# Inisialisasi model saat aplikasi dimulai
load_model_and_labels()

@app.route('/')
def home():
    return jsonify({'message': 'Web Service SmartWaste Kids Aktif!'})

# --- AUTH ENDPOINTS ---

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [username])
    user = cur.fetchone()
    
    if user is None:
        cur.close()
        return jsonify({'message': 'Username Salah'}), 401

    if not check_password_hash(user['password_hash'], password):
        cur.close()
        return jsonify({'message': 'Password Salah'}), 401

    cur.close()
    user_data = {
        'id': user['id'],
        'nama_lengkap': user['nama_lengkap'],
        'email': user['email'],
        'username': user['username']
    }
    
    return jsonify(user_data)

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    nama_lengkap = data['nama_lengkap']
    email = data['email']
    username = data['username']
    password = data['password']
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s OR username = %s", (email, username))
    user = cur.fetchone()
    
    if user:
        cur.close()
        return jsonify({'message': 'Email atau username sudah terdaftar!'}), 400

    password_hash = generate_password_hash(password)
    
    cur.execute(
        "INSERT INTO users (nama_lengkap, email, username, password_hash) VALUES (%s, %s, %s, %s)",
        (nama_lengkap, email, username, password_hash)
    )
    mysql.connection.commit()
    
    new_user_id = cur.lastrowid
    cur.execute("SELECT id, nama_lengkap, email, username FROM users WHERE id = %s", [new_user_id])
    new_user_data = cur.fetchone()
    
    cur.close()
    
    return jsonify(new_user_data), 201

@app.route('/api/auth/google', methods=['POST'])
def google_login():
    data = request.json
    email = data.get('email')
    google_id = data.get('google_id')
    nama_lengkap = data.get('nama_lengkap')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cur.fetchone()

    if user:
        if user['google_id'] is None:
            cur.execute("UPDATE users SET google_id = %s WHERE id = %s", 
                        (google_id, user['id']))
            mysql.connection.commit()
            cur.execute("SELECT * FROM users WHERE id = %s", [user['id']])
            user = cur.fetchone()

        cur.close()
        
        return jsonify({
            'status': 'login_sukses',
            'message': 'Berhasil Login dengan Google',
            'data': {
                'id': user['id'],
                'nama_lengkap': user['nama_lengkap'],
                'email': user['email'],
                'username': user['username']
            }
        }), 200

    else:
        base_username = email.split('@')[0] 
        random_suffix = ''.join(random.choices(string.digits, k=3)) 
        new_username = base_username + random_suffix

        try:
            cur.execute(
                "INSERT INTO users (nama_lengkap, email, username, google_id) VALUES (%s, %s, %s, %s)",
                (nama_lengkap, email, new_username, google_id)
            )
            mysql.connection.commit()
            new_user_id = cur.lastrowid
            cur.close()

            return jsonify({
                'status': 'register_sukses',
                'message': 'Akun baru berhasil dibuat dari Google',
                'data': {
                    'id': new_user_id,
                    'nama_lengkap': nama_lengkap,
                    'email': email,
                    'username': new_username
                }
            }), 201
            
        except Exception as e:
            cur.close()
            return jsonify({'message': 'Gagal membuat user Google: ' + str(e)}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def request_otp():
    data = request.json
    email = data.get('email')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        return jsonify({'message': 'Email tidak terdaftar!'}), 404

    otp = ''.join(random.choices(string.digits, k=6))
    
    try:
        cur.execute("UPDATE users SET otp_code = %s WHERE email = %s", (otp, email))
        mysql.connection.commit()
        cur.close()
        
        msg = Message('Kode OTP Reset Password - SmartWaste', 
                      sender=app.config['MAIL_USERNAME'], 
                      recipients=[email])
        msg.body = f"Halo {user['nama_lengkap']},\n\nKode OTP untuk reset password Anda adalah: {otp}\n\nJangan berikan kode ini ke siapapun."
        mail.send(msg)
        
        return jsonify({'message': 'Kode OTP telah dikirim ke email Anda!'}), 200
    except Exception as e:
        return jsonify({'message': 'Gagal mengirim email: ' + str(e)}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def verify_reset_password():
    data = request.json
    email = data.get('email')
    otp_input = data.get('otp')
    new_password = data.get('new_password')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        return jsonify({'message': 'User tidak ditemukan'}), 404
        
    if user['otp_code'] != otp_input:
        cur.close()
        return jsonify({'message': 'Kode OTP Salah!'}), 400
        
    new_hash = generate_password_hash(new_password)
    
    try:
        cur.execute("UPDATE users SET password_hash = %s, otp_code = NULL WHERE email = %s", (new_hash, email))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message': 'Password berhasil diubah! Silakan login.'}), 200
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error database: ' + str(e)}), 500

# --- USER ENDPOINTS ---

@app.route('/api/users/profile', methods=['GET'])
def get_user_profile():
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'message': 'User ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama_lengkap, email, username FROM users WHERE id = %s", [user_id])
    user = cur.fetchone()
    cur.close()
    
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404
    
    return jsonify(user), 200

@app.route('/api/users/profile', methods=['PUT'])
def update_user_profile():
    data = request.json
    user_id = data.get('user_id')
    nama_lengkap = data.get('nama_lengkap')
    email = data.get('email')
    
    if not user_id:
        return jsonify({'message': 'User ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        return jsonify({'message': 'User tidak ditemukan'}), 404
    
    try:
        cur.execute(
            "UPDATE users SET nama_lengkap = %s, email = %s WHERE id = %s",
            (nama_lengkap, email, user_id)
        )
        mysql.connection.commit()
        
        cur.execute("SELECT id, nama_lengkap, email, username FROM users WHERE id = %s", [user_id])
        updated_user = cur.fetchone()
        cur.close()
        
        return jsonify(updated_user), 200
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error saat update profile: ' + str(e)}), 500

@app.route('/api/users/activities', methods=['GET'])
def get_user_activities():
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'message': 'User ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT a.*, w.nama as nama_sampah, w.kategori 
        FROM user_activities a 
        JOIN waste_items w ON a.waste_id = w.waste_id 
        WHERE a.user_id = %s 
        ORDER BY a.tanggal DESC
    """, [user_id])
    activities = cur.fetchall()
    cur.close()
    
    return jsonify(activities), 200

@app.route('/api/auth/user/<userId>', methods=['GET'])
def get_user(userId):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama_lengkap, email, username FROM users WHERE id = %s", [userId])
    user = cur.fetchone()
    cur.close()
    
    if not user:
        return jsonify({'message': 'User tidak ditemukan'}), 404
    
    return jsonify(user), 200

@app.route('/api/auth/user/<userId>/profile', methods=['PUT'])
def update_profile(userId):
    data = request.json
    nama_lengkap = data.get('nama_lengkap')
    email = data.get('email')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [userId])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        return jsonify({'message': 'User tidak ditemukan'}), 404
    
    try:
        cur.execute(
            "UPDATE users SET nama_lengkap = %s, email = %s WHERE id = %s",
            (nama_lengkap, email, userId)
        )
        mysql.connection.commit()
        
        cur.execute("SELECT id, nama_lengkap, email, username FROM users WHERE id = %s", [userId])
        updated_user = cur.fetchone()
        cur.close()
        
        return jsonify(updated_user), 200
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error saat update profile: ' + str(e)}), 500

@app.route('/api/auth/user/<userId>/password', methods=['PUT'])
def change_password(userId):
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'message': 'Password lama dan baru diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [userId])
    user = cur.fetchone()
    
    if not user:
        cur.close()
        return jsonify({'message': 'User tidak ditemukan'}), 404
    
    if not check_password_hash(user['password_hash'], current_password):
        cur.close()
        return jsonify({'message': 'Password lama salah'}), 401
    
    try:
        new_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, userId))
        mysql.connection.commit()
        cur.close()
        
        return jsonify({'message': 'Password berhasil diubah'}), 200
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error saat ubah password: ' + str(e)}), 500

# --- WASTE ENDPOINTS ---

@app.route('/api/waste-categories', methods=['GET'])
def get_waste_categories():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM waste_categories")
    categories = cur.fetchall()
    cur.close()
    
    return jsonify(categories), 200

@app.route('/api/waste-items', methods=['GET'])
def get_waste_items():
    category_id = request.args.get('category_id')
    
    cur = mysql.connection.cursor()
    
    if category_id:
        cur.execute("SELECT * FROM waste_items WHERE category_id = %s", [category_id])
    else:
        cur.execute("SELECT * FROM waste_items")
    
    items = cur.fetchall()
    cur.close()
    
    return jsonify(items), 200

@app.route('/api/waste-items/label', methods=['GET'])
def get_waste_by_label():
    label = request.args.get('label')
    
    if not label:
        return jsonify({'message': 'Label diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM waste_items WHERE model_label = %s", [label])
    items = cur.fetchall()
    cur.close()
    
    return jsonify(items), 200

@app.route('/api/user-activities', methods=['POST'])
def log_activity():
    data = request.json
    user_id = data.get('user_id')
    waste_id = data.get('waste_id')
    points = data.get('points', 0)
    
    if not user_id or not waste_id:
        return jsonify({'message': 'User ID dan Waste ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    
    try:
        cur.execute(
            "INSERT INTO user_activities (user_id, waste_id, points, tanggal) VALUES (%s, %s, %s, NOW())",
            (user_id, waste_id, points)
        )
        mysql.connection.commit()
        
        cur.execute("UPDATE users SET total_points = total_points + %s WHERE id = %s", (points, user_id))
        mysql.connection.commit()
        
        activity_id = cur.lastrowid
        cur.close()
        
        return jsonify({
            'message': 'Aktivitas berhasil dicatat',
            'activity_id': activity_id
        }), 201
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error saat mencatat aktivitas: ' + str(e)}), 500

@app.route('/api/auth/waste/categories', methods=['GET'])
def get_waste_categories_alt():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM waste_categories")
    categories = cur.fetchall()
    cur.close()
    
    return jsonify(categories), 200

@app.route('/api/auth/waste/items', methods=['GET'])
def get_waste_items_alt():
    category_id = request.args.get('category_id')
    
    cur = mysql.connection.cursor()
    
    if category_id:
        cur.execute("SELECT * FROM waste_items WHERE category_id = %s", [category_id])
    else:
        cur.execute("SELECT * FROM waste_items")
    
    items = cur.fetchall()
    cur.close()
    
    return jsonify(items), 200

# --- ACHIEVEMENT ENDPOINTS ---

@app.route('/api/achievements', methods=['GET'])
def get_achievements():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM achievements")
    achievements = cur.fetchall()
    cur.close()
    
    return jsonify(achievements), 200

@app.route('/api/user-achievements', methods=['GET'])
def get_user_achievements():
    user_id = request.args.get('user_id')
    
    if not user_id:
        return jsonify({'message': 'User ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT ua.*, a.nama, a.deskripsi, a.poin_reward, a.icon
        FROM user_achievements ua
        JOIN achievements a ON ua.achievement_id = a.id
        WHERE ua.user_id = %s
    """, [user_id])
    user_achievements = cur.fetchall()
    cur.close()
    
    return jsonify(user_achievements), 200

@app.route('/api/user-achievements/unlock', methods=['POST'])
def unlock_achievement():
    data = request.json
    user_id = data.get('user_id')
    achievement_id = data.get('achievement_id')
    
    if not user_id or not achievement_id:
        return jsonify({'message': 'User ID dan Achievement ID diperlukan'}), 400
    
    cur = mysql.connection.cursor()
    
    cur.execute(
        "SELECT * FROM user_achievements WHERE user_id = %s AND achievement_id = %s",
        (user_id, achievement_id)
    )
    existing = cur.fetchone()
    
    if existing:
        cur.close()
        return jsonify({'message': 'Achievement sudah diunlock'}), 400
    
    try:
        cur.execute(
            "INSERT INTO user_achievements (user_id, achievement_id, tanggal_unlock) VALUES (%s, %s, NOW())",
            (user_id, achievement_id)
        )
        
        cur.execute("SELECT poin_reward FROM achievements WHERE id = %s", [achievement_id])
        achievement = cur.fetchone()
        
        cur.execute("UPDATE users SET total_points = total_points + %s WHERE id = %s", 
                   (achievement['poin_reward'], user_id))
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({'message': 'Achievement berhasil diunlock'}), 201
    except Exception as e:
        cur.close()
        return jsonify({'message': 'Error saat unlock achievement: ' + str(e)}), 500

# --- BIN ENDPOINTS ---

@app.route('/api/bins', methods=['GET'])
def get_bins():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM bins")
    bins = cur.fetchall()
    cur.close()
    
    return jsonify(bins), 200

# --- PREDICTION ENDPOINT (FINAL VERSION) ---

@app.route('/api/waste/predict', methods=['POST'])
def predict_waste():
    print("--- Permintaan prediksi diterima ---")
    
    if model is None or not class_labels:
        print("ERROR: Model atau label tidak dimuat.")
        return jsonify({'error': 'Model atau label tidak dimuat. Cek server log.'}), 500

    if 'image' not in request.files:
        print("ERROR: Tidak ada file 'image' dalam request.")
        return jsonify({'error': 'Tidak ada file gambar yang dikirim'}), 400
    
    file = request.files['image']
    user_id = request.form.get('user_id')

    if file.filename == '':
        print("ERROR: Nama file kosong.")
        return jsonify({'error': 'Nama file kosong'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            print(f"Menyimpan file ke: {filepath}")
            file.save(filepath)
        except Exception as e:
            print(f"ERROR Gagal menyimpan file: {e}")
            return jsonify({'error': f'Gagal menyimpan file: {str(e)}'}), 500

        try:
            print("Melakukan preprocessing gambar...")
            processed_image = preprocess_image(filepath)

            print("Melakukan prediksi dengan model...")
            predictions = model.predict(processed_image)
            scores = predictions[0]
            predicted_index = np.argmax(scores)
            confidence = float(np.max(scores))
            predicted_label = class_labels[predicted_index]
            print(f"Hasil prediksi: {predicted_label} dengan confidence: {confidence}")

            print("Mengquery database untuk detail sampah...")
            cur = mysql.connection.cursor()
            # PERBAIKAN: Hapus wi.color_code karena kolom tidak ada di DB
            query = """
                SELECT 
                    wi.waste_id,
                    wi.waste_name,
                    wi.model_label,
                    wi.category_id,
                    wc.category_name,
                    wi.decomposition_time,
                    wi.description,
                    wi.fun_fact,
                    wi.image_url
                FROM waste_items wi
                JOIN waste_categories wc ON wi.category_id = wc.id
                WHERE wi.model_label = %s
            """
            cur.execute(query, [predicted_label])
            waste_details = cur.fetchone()
            cur.close()

            if not waste_details:
                print(f"ERROR: Detail untuk label '{predicted_label}' tidak ditemukan di DB.")
                if os.path.exists(filepath): os.remove(filepath)
                return jsonify({'success': False, 'message': f'Detail untuk jenis sampah "{predicted_label}" tidak ditemukan di database.'}), 404

            serializable_details = {key: str(value) for key, value in waste_details.items()}
            print("Detail sampah berhasil disiapkan untuk dikirim.")

            response_data = {
                'success': True,
                'waste_type': predicted_label,
                'confidence': confidence,
                'image_path': filepath,
                'waste_details': serializable_details,
                'all_results': []
            }
            print("Mengirim response sukses.")
            return jsonify(response_data), 200

        except Exception as e:
            print(f"ERROR saat proses prediksi atau query DB: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': f'Gagal saat proses prediksi: {str(e)}'}), 500

    else:
        print("ERROR: Tipe file tidak diizinkan.")
        return jsonify({'error': 'Tipe file tidak diizinkan'}), 400

# --- ACTIVITY & LEADERBOARD ENDPOINTS ---

@app.route('/api/auth/activity', methods=['GET'])
def get_activities():
    user_id = request.args.get('user_id')
    
    cur = mysql.connection.cursor()
    
    if user_id:
        cur.execute("""
            SELECT a.*, w.nama as nama_sampah, w.kategori 
            FROM user_activities a 
            JOIN waste_items w ON a.waste_id = w.waste_id 
            WHERE a.user_id = %s 
            ORDER BY a.tanggal DESC
        """, [user_id])
    else:
        cur.execute("""
            SELECT a.*, u.username, w.nama as nama_sampah, w.kategori 
            FROM user_activities a 
            JOIN users u ON a.user_id = u.id 
            JOIN waste_items w ON a.waste_id = w.waste_id 
            ORDER BY a.tanggal DESC
        """)
    
    activities = cur.fetchall()
    cur.close()
    
    return jsonify(activities), 200

@app.route('/api/auth/leaderboard', methods=['GET'])
def get_leaderboard():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, username, nama_lengkap, total_points 
        FROM users 
        WHERE total_points > 0
        ORDER BY total_points DESC
        LIMIT 10
    """)
    leaderboard = cur.fetchall()
    cur.close()
    
    return jsonify(leaderboard), 200

# --- EDUCATION ENDPOINTS ---

@app.route('/api/waste-education', methods=['GET'])
def get_education_contents():
    """Mendapatkan semua konten edukasi"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM waste_education ORDER BY created_at DESC")
        education_contents = cur.fetchall()
        cur.close()
        
        return jsonify({
            'success': True,
            'data': education_contents
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat mengambil konten edukasi: {str(e)}'
        }), 500

@app.route('/api/waste-education/<int:content_id>', methods=['GET'])
def get_education_content_by_id(content_id):
    """Mendapatkan konten edukasi berdasarkan ID"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM waste_education WHERE id = %s", [content_id])
        education_content = cur.fetchone()
        cur.close()
        
        if not education_content:
            return jsonify({
                'success': False,
                'message': 'Konten edukasi tidak ditemukan'
            }), 404
        
        return jsonify({
            'success': True,
            'data': education_content
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat mengambil konten edukasi: {str(e)}'
        }), 500

@app.route('/api/waste-education/category/<category>', methods=['GET'])
def get_education_by_category(category):
    """Mendapatkan konten edukasi berdasarkan kategori"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM waste_education WHERE category = %s ORDER BY created_at DESC", [category])
        education_contents = cur.fetchall()
        cur.close()
        
        return jsonify({
            'success': True,
            'data': education_contents
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat mengambil konten edukasi: {str(e)}'
        }), 500

@app.route('/api/waste-education', methods=['POST'])
def create_education_content():
    """Membuat konten edukasi baru (untuk admin)"""
    data = request.json
    title = data.get('title')
    content = data.get('content')
    image_url = data.get('image_url')
    category = data.get('category')
    
    if not title or not content or not category:
        return jsonify({
            'success': False,
            'message': 'Title, content, dan category diperlukan'
        }), 400
    
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO waste_education (title, content, image_url, category, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (title, content, image_url, category)
        )
        mysql.connection.commit()
        
        new_content_id = cur.lastrowid
        cur.execute("SELECT * FROM waste_education WHERE id = %s", [new_content_id])
        new_content = cur.fetchone()
        cur.close()
        
        return jsonify({
            'success': True,
            'message': 'Konten edukasi berhasil dibuat',
            'data': new_content
        }), 201
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat membuat konten edukasi: {str(e)}'
        }), 500

@app.route('/api/waste-education/<int:content_id>', methods=['PUT'])
def update_education_content(content_id):
    """Memperbarui konten edukasi (untuk admin)"""
    data = request.json
    title = data.get('title')
    content = data.get('content')
    image_url = data.get('image_url')
    category = data.get('category')
    
    try:
        cur = mysql.connection.cursor()
        
        # Periksa apakah konten ada
        cur.execute("SELECT * FROM waste_education WHERE id = %s", [content_id])
        existing_content = cur.fetchone()
        
        if not existing_content:
            cur.close()
            return jsonify({
                'success': False,
                'message': 'Konten edukasi tidak ditemukan'
            }), 404
        
        # Update konten
        cur.execute(
            "UPDATE waste_education SET title = %s, content = %s, image_url = %s, category = %s WHERE id = %s",
            (title, content, image_url, category, content_id)
        )
        mysql.connection.commit()
        
        # Ambil data yang sudah diupdate
        cur.execute("SELECT * FROM waste_education WHERE id = %s", [content_id])
        updated_content = cur.fetchone()
        cur.close()
        
        return jsonify({
            'success': True,
            'message': 'Konten edukasi berhasil diperbarui',
            'data': updated_content
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat memperbarui konten edukasi: {str(e)}'
        }), 500

@app.route('/api/waste-education/<int:content_id>', methods=['DELETE'])
def delete_education_content(content_id):
    """Menghapus konten edukasi (untuk admin)"""
    try:
        cur = mysql.connection.cursor()
        
        # Periksa apakah konten ada
        cur.execute("SELECT * FROM waste_education WHERE id = %s", [content_id])
        existing_content = cur.fetchone()
        
        if not existing_content:
            cur.close()
            return jsonify({
                'success': False,
                'message': 'Konten edukasi tidak ditemukan'
            }), 404
        
        # Hapus konten
        cur.execute("DELETE FROM waste_education WHERE id = %s", [content_id])
        mysql.connection.commit()
        cur.close()
        
        return jsonify({
            'success': True,
            'message': 'Konten edukasi berhasil dihapus'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error saat menghapus konten edukasi: {str(e)}'
        }), 500

@app.route('/cek-koneksi')
def cek_koneksi():
    try:
        cur = mysql.connection.cursor()
        cur.execute('SELECT 1')
        cur.close()
        return jsonify({'status': 'sukses', 'message': 'Database MySQL berhasil terkoneksi!'})
    except Exception as e:
        return jsonify({'status': 'gagal', 'message': str(e)}), 500

# --- 4. Jalankan Server ---
if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')