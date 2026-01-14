from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import random   
import string
import os
import time
from werkzeug.utils import secure_filename
import numpy as np
from PIL import Image
import tensorflow as tf
import json
from dotenv import load_dotenv
import logging

# Setup logging
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')

# Load environment variables
load_dotenv()

# --- 1. Buat Aplikasi Flask ---
app = Flask(__name__) 
# Izinkan Flutter (dari domain lain) untuk mengakses API ini
CORS(app) 

# --- 2. Konfigurasi Database MySQL ---
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', '127.0.0.1') 
app.config['MYSQL_PORT'] = int(os.environ.get('MYSQL_PORT', 3307))
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'smartwastekids_db')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # Agar hasilnya berupa JSON

# --- KONFIGURASI EMAIL (GMAIL) ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 465))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'smartwastekids@gmail.com') 
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '') # Gunakan App Password di production
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Konfigurasi JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'smartwastekids-secret-key') # Ganti dengan ENV di production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # Token tidak kedaluwarsa, sesuaikan sesuai kebutuhan
jwt = JWTManager(app)

# Konfigurasi untuk upload file
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Path ke model dan label
MODEL_PATH = 'data/model_sampahmobilenet.h5'
LABELS_PATH = 'data/labels.json'
CONFIDENCE_THRESHOLD = 0.6

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
    global model, class_labels
    try:
        logging.info("Loading TensorFlow .h5 model...")
        model = tf.keras.models.load_model(MODEL_PATH, compile=False)

        with open(LABELS_PATH, 'r') as f:
            class_labels = json.load(f)

        logging.info("Model & labels loaded successfully")
        return True
    except Exception as e:
        logging.error(f"ERROR loading model: {str(e)}")
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
    try:
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

        # Generate JWT token
        access_token = create_access_token(identity=user['id_users'])
        
        cur.close()
        user_data = {
            'id_users': user['id_users'],
            'nama_lengkap': user['nama_lengkap'],
            'email': user['email'],
            'username': user['username'],
            'role': user['role'],
            'current_level': user['current_level'],
            'foto_profile': user['foto_profile']
        }
        
        return jsonify({
            'user': user_data,
            'token': access_token
        }), 200
    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat login'}), 500

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
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
        cur.execute("SELECT id_users, nama_lengkap, email, username, current_level FROM users WHERE id_users = %s", [new_user_id])
        new_user_data = cur.fetchone()
        
        # Generate JWT token
        access_token = create_access_token(identity=new_user_id)
        
        cur.close()
        
        return jsonify({
            'user': new_user_data,
            'token': access_token
        }), 201
    except Exception as e:
        logging.error(f"Register error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat registrasi'}), 500

@app.route('/api/auth/google', methods=['POST'])
def google_login():
    try:
        data = request.json
        email = data.get('email')
        google_id = data.get('google_id')
        nama_lengkap = data.get('nama_lengkap')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()

        if user:
            if user['google_id'] is None:
                cur.execute("UPDATE users SET google_id = %s WHERE id_users = %s", 
                            (google_id, user['id_users']))
                mysql.connection.commit()
                cur.execute("SELECT * FROM users WHERE id_users = %s", [user['id_users']])
                user = cur.fetchone()

            # Generate JWT token
            access_token = create_access_token(identity=user['id_users'])
            
            cur.close()
            
            return jsonify({
                'success': True,
                'message': 'Berhasil Login dengan Google',
                'user': {
                    'id_users': user['id_users'],
                    'nama_lengkap': user['nama_lengkap'],
                    'email': user['email'],
                    'username': user['username'],
                    'role': user['role'],
                    'current_level': user['current_level']
                },
                'token': access_token
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
                
                # Generate JWT token
                access_token = create_access_token(identity=new_user_id)
                
                cur.close()

                return jsonify({
                    'success': True,
                    'message': 'Akun baru berhasil dibuat dari Google',
                    'user': {
                        'id_users': new_user_id,
                        'nama_lengkap': nama_lengkap,
                        'email': email,
                        'username': new_username
                    },
                    'token': access_token
                }), 201
                
            except Exception as e:
                cur.close()
                logging.error(f"Google login error: {str(e)}")
                return jsonify({'message': 'Gagal membuat user Google: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Google login error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat login dengan Google'}), 500

@app.route('/api/auth/forgot-password', methods=['POST'])
def request_otp():
    try:
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
            logging.error(f"Email sending error: {str(e)}")
            return jsonify({'message': 'Gagal mengirim email: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Forgot password error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat meminta OTP'}), 500

@app.route('/api/auth/reset-password', methods=['POST'])
def verify_reset_password():
    try:
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
            logging.error(f"Database error: {str(e)}")
            cur.close()
            return jsonify({'message': 'Error database: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Reset password error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat reset password'}), 500

# --- USER ENDPOINTS ---

# Menggabungkan endpoint profile yang redundan
@app.route('/api/users/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    try:
        current_user_id = get_jwt_identity()
        
        if request.method == 'GET':
            cur = mysql.connection.cursor()
            cur.execute("SELECT id_users, nama_lengkap, email, username, role, current_level, foto_profile FROM users WHERE id_users = %s", [current_user_id])
            user = cur.fetchone()
            cur.close()
            
            if not user:
                return jsonify({'message': 'User tidak ditemukan'}), 404
            
            return jsonify(user), 200
            
        elif request.method == 'PUT':
            data = request.json
            nama_lengkap = data.get('nama_lengkap')
            email = data.get('email')
            
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM users WHERE id_users = %s", [current_user_id])
            user = cur.fetchone()
            
            if not user:
                cur.close()
                return jsonify({'message': 'User tidak ditemukan'}), 404
            
            try:
                cur.execute(
                    "UPDATE users SET nama_lengkap = %s, email = %s WHERE id_users = %s",
                    (nama_lengkap, email, current_user_id)
                )
                mysql.connection.commit()
                
                cur.execute("SELECT id_users, nama_lengkap, email, username, role, current_level, foto_profile FROM users WHERE id_users = %s", [current_user_id])
                updated_user = cur.fetchone()
                cur.close()
                
                return jsonify(updated_user), 200
            except Exception as e:
                logging.error(f"Profile update error: {str(e)}")
                cur.close()
                return jsonify({'message': 'Error saat update profile: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Profile error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan pada profile endpoint'}), 500

@app.route('/api/users/password', methods=['PUT'])
@jwt_required()
def change_password():
    try:
        current_user_id = get_jwt_identity()
        data = request.json
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'message': 'Password lama dan baru diperlukan'}), 400
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE id_users = %s", [current_user_id])
        user = cur.fetchone()
        
        if not user:
            cur.close()
            return jsonify({'message': 'User tidak ditemukan'}), 404
        
        if not check_password_hash(user['password_hash'], current_password):
            cur.close()
            return jsonify({'message': 'Password lama salah'}), 401
        
        try:
            new_hash = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password_hash = %s WHERE id_users = %s", (new_hash, current_user_id))
            mysql.connection.commit()
            cur.close()
            
            return jsonify({'message': 'Password berhasil diubah'}), 200
        except Exception as e:
            logging.error(f"Password change error: {str(e)}")
            cur.close()
            return jsonify({'message': 'Error saat ubah password: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Password change error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengubah password'}), 500

@app.route('/api/users/activities', methods=['GET'])
@jwt_required()
def get_user_activities():
    try:
        current_user_id = get_jwt_identity()
        
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT ua.*, s.nama_sampah, ks.jenis_sampah 
            FROM users_aktivitas ua 
            JOIN sampah s ON ua.id_sampah = s.id_sampah 
            JOIN kategori_sampah ks ON s.id_kategori = ks.id_kategori
            WHERE ua.id_users = %s 
            ORDER BY ua.waktu_aktivitas DESC
        """, [current_user_id])
        activities = cur.fetchall()
        cur.close()
        
        return jsonify(activities), 200
    except Exception as e:
        logging.error(f"Get activities error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil aktivitas'}), 500

# --- WASTE ENDPOINTS ---

@app.route('/api/waste-categories', methods=['GET'])
def get_waste_categories():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM kategori_sampah")
        categories = cur.fetchall()
        cur.close()
        
        return jsonify(categories), 200
    except Exception as e:
        logging.error(f"Get waste categories error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil kategori sampah'}), 500

@app.route('/api/waste-items', methods=['GET'])
def get_waste_items():
    try:
        category_id = request.args.get('category_id')
        
        cur = mysql.connection.cursor()
        
        if category_id:
            cur.execute("SELECT * FROM sampah WHERE id_kategori = %s", [category_id])
        else:
            cur.execute("SELECT * FROM sampah")
        
        items = cur.fetchall()
        cur.close()
        
        return jsonify(items), 200
    except Exception as e:
        logging.error(f"Get waste items error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil item sampah'}), 500

@app.route('/api/waste-items/label', methods=['GET'])
def get_waste_by_label():
    try:
        label = request.args.get('label')
        
        if not label:
            return jsonify({'message': 'Label diperlukan'}), 400
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM sampah WHERE model_label = %s", [label])
        items = cur.fetchall()
        cur.close()
        
        return jsonify(items), 200
    except Exception as e:
        logging.error(f"Get waste by label error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil sampah berdasarkan label'}), 500

@app.route('/api/user-activities', methods=['POST'])
@jwt_required()
def log_activity():
    try:
        current_user_id = get_jwt_identity()
        data = request.json
        waste_id = data.get('waste_id')
        
        if not waste_id:
            return jsonify({'message': 'Waste ID diperlukan'}), 400
        
        cur = mysql.connection.cursor()
        
        try:
            cur.execute(
                "INSERT INTO users_aktivitas (id_users, id_sampah, waktu_aktivitas) VALUES (%s, %s, NOW())",
                (current_user_id, waste_id)
            )
            mysql.connection.commit()
            
            # Update user level based on activities count
            cur.execute("SELECT COUNT(*) as activity_count FROM users_aktivitas WHERE id_users = %s", [current_user_id])
            activity_count = cur.fetchone()['activity_count']
            
            # Determine new level based on activity count
            cur.execute("SELECT id_level FROM level_user WHERE point_min <= %s AND point_max >= %s", 
                       (activity_count, activity_count))
            level_data = cur.fetchone()
            
            if level_data:
                new_level = level_data['id_level']
                cur.execute("UPDATE users SET current_level = %s WHERE id_users = %s", (new_level, current_user_id))
                mysql.connection.commit()
            
            activity_id = cur.lastrowid
            cur.close()
            
            return jsonify({
                'message': 'Aktivitas berhasil dicatat',
                'activity_id': activity_id
            }), 201
        except Exception as e:
            logging.error(f"Log activity error: {str(e)}")
            cur.close()
            return jsonify({'message': 'Error saat mencatat aktivitas: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Log activity error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mencatat aktivitas'}), 500

# --- ACHIEVEMENT ENDPOINTS ---

@app.route('/api/achievements', methods=['GET'])
def get_achievements():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM penghargaan")
        achievements = cur.fetchall()
        cur.close()
        
        return jsonify(achievements), 200
    except Exception as e:
        logging.error(f"Get achievements error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil penghargaan'}), 500

@app.route('/api/user-achievements', methods=['GET'])
@jwt_required()
def get_user_achievements():
    try:
        current_user_id = get_jwt_identity()
        
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT pu.*, p.judul_penghargaan, p.deskripsi_penghargaan, p.poin_penghargaan, p.badge_assets
            FROM penghargaan_users pu
            JOIN penghargaan p ON pu.id_penghargaan = p.id_penghargaan
            WHERE pu.id_users = %s
        """, [current_user_id])
        user_achievements = cur.fetchall()
        cur.close()
        
        return jsonify(user_achievements), 200
    except Exception as e:
        logging.error(f"Get user achievements error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil penghargaan user'}), 500

@app.route('/api/user-achievements/unlock', methods=['POST'])
@jwt_required()
def unlock_achievement():
    try:
        current_user_id = get_jwt_identity()
        data = request.json
        achievement_id = data.get('achievement_id')
        
        if not achievement_id:
            return jsonify({'message': 'Achievement ID diperlukan'}), 400
        
        cur = mysql.connection.cursor()
        
        cur.execute(
            "SELECT * FROM penghargaan_users WHERE id_users = %s AND id_penghargaan = %s",
            (current_user_id, achievement_id)
        )
        existing = cur.fetchone()
        
        if existing:
            cur.close()
            return jsonify({'message': 'Achievement sudah diunlock'}), 400
        
        try:
            cur.execute(
                "INSERT INTO penghargaan_users (id_users, id_penghargaan, poin_penghargaan, status_target) VALUES (%s, %s, (SELECT poin_penghargaan FROM penghargaan WHERE id_penghargaan = %s), 1)",
                (current_user_id, achievement_id, achievement_id)
            )
            
            cur.execute("SELECT poin_penghargaan FROM penghargaan WHERE id_penghargaan = %s", [achievement_id])
            achievement = cur.fetchone()
            
            # Update user level based on total points
            cur.execute("SELECT SUM(p.poin_penghargaan) as total_points FROM penghargaan_users pu JOIN penghargaan p ON pu.id_penghargaan = p.id_penghargaan WHERE pu.id_users = %s", [current_user_id])
            total_points = cur.fetchone()['total_points']
            
            cur.execute("SELECT id_level FROM level_user WHERE point_min <= %s AND point_max >= %s", 
                       (total_points, total_points))
            level_data = cur.fetchone()
            
            if level_data:
                new_level = level_data['id_level']
                cur.execute("UPDATE users SET current_level = %s WHERE id_users = %s", (new_level, current_user_id))
            
            mysql.connection.commit()
            cur.close()
            
            return jsonify({'message': 'Achievement berhasil diunlock'}), 201
        except Exception as e:
            logging.error(f"Unlock achievement error: {str(e)}")
            cur.close()
            return jsonify({'message': 'Error saat unlock achievement: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"Unlock achievement error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat unlock achievement'}), 500

# --- BIN ENDPOINTS ---

@app.route('/api/bins', methods=['GET'])
def get_bins():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM bins")
        bins = cur.fetchall()
        cur.close()
        
        return jsonify(bins), 200
    except Exception as e:
        logging.error(f"Get bins error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil data bin'}), 500

# ======================================================
# PREDICT ENDPOINT (UPDATED)
# ======================================================
@app.route('/api/waste/predict', methods=['POST'])
@jwt_required()
def predict_waste():
    try:
        if model is None or not class_labels:
            return jsonify({'error': 'Model belum siap'}), 500

        if 'image' not in request.files:
            return jsonify({'error': 'File gambar tidak ditemukan'}), 400

        file = request.files['image']
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({'error': 'File tidak valid'}), 400

        filename = secure_filename(file.filename)
        unique_name = f"{int(time.time())}_{filename}"
        path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
        file.save(path)

        try:
            img = preprocess_image(path)
            preds = model.predict(img)[0]

            idx = int(np.argmax(preds))
            confidence = float(np.max(preds))
            label = class_labels[idx]

            if confidence < CONFIDENCE_THRESHOLD:
                os.remove(path)
                return jsonify({
                    'success': False,
                    'message': 'Gambar tidak dikenali dengan yakin',
                    'confidence': confidence
                }), 422

            cur = mysql.connection.cursor()
            query = """
                SELECT 
                    s.id_sampah,
                    s.nama_sampah,
                    s.id_kategori,
                    ks.jenis_sampah,
                    s.lama_terurai,
                    s.deskripsi_sampah,
                    s.manfaat_sampah,
                    s.gambar
                FROM sampah s
                JOIN kategori_sampah ks 
                    ON s.id_kategori = ks.id_kategori
                WHERE s.nama_sampah LIKE %s
            """
            cur.execute(query, [f"%{label}%"])
            data = cur.fetchone()
            cur.close()

            if not data:
                os.remove(path)
                return jsonify({
                    'success': False,
                    'message': f'Data untuk label "{label}" tidak ditemukan'
                }), 404

            os.remove(path)

            return jsonify({
                'success': True,
                'waste_type': label,
                'confidence': confidence,
                'waste_details': data
            }), 200

        except Exception as e:
            logging.error(f"Prediction error: {str(e)}")
            if os.path.exists(path):
                os.remove(path)
            return jsonify({'error': str(e)}), 500
    except Exception as e:
        logging.error(f"Predict endpoint error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat prediksi'}), 500

# --- ACTIVITY & LEADERBOARD ENDPOINTS ---

@app.route('/api/activities', methods=['GET'])
def get_activities():
    try:
        user_id = request.args.get('user_id')
        
        cur = mysql.connection.cursor()
        
        if user_id:
            cur.execute("""
                SELECT ua.*, u.username, s.nama_sampah, ks.jenis_sampah 
                FROM users_aktivitas ua 
                JOIN users u ON ua.id_users = u.id_users 
                JOIN sampah s ON ua.id_sampah = s.id_sampah
                JOIN kategori_sampah ks ON s.id_kategori = ks.id_kategori
                WHERE ua.id_users = %s 
                ORDER BY ua.waktu_aktivitas DESC
            """, [user_id])
        else:
            cur.execute("""
                SELECT ua.*, u.username, s.nama_sampah, ks.jenis_sampah 
                FROM users_aktivitas ua 
                JOIN users u ON ua.id_users = u.id_users 
                JOIN sampah s ON ua.id_sampah = s.id_sampah
                JOIN kategori_sampah ks ON s.id_kategori = ks.id_kategori
                ORDER BY ua.waktu_aktivitas DESC
            """)
        
        activities = cur.fetchall()
        cur.close()
        
        return jsonify(activities), 200
    except Exception as e:
        logging.error(f"Get activities error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil aktivitas'}), 500

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT u.id_users, u.username, u.nama_lengkap, u.current_level, COUNT(ua.id_aktivitas) as activity_count
            FROM users u
            LEFT JOIN users_aktivitas ua ON u.id_users = ua.id_users
            GROUP BY u.id_users
            ORDER BY activity_count DESC
            LIMIT 10
        """)
        leaderboard = cur.fetchall()
        cur.close()
        
        return jsonify(leaderboard), 200
    except Exception as e:
        logging.error(f"Get leaderboard error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil leaderboard'}), 500

# --- EDUCATION ENDPOINTS ---

@app.route('/api/waste-education', methods=['GET', 'POST'])
def education_contents():
    try:
        if request.method == 'GET':
            """Mendapatkan semua konten edukasi"""
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM edukasi ORDER BY id_edukasi DESC")
            education_contents = cur.fetchall()
            cur.close()
            
            return jsonify({
                'success': True,
                'data': education_contents
            }), 200
            
        elif request.method == 'POST':
            """Membuat konten edukasi baru (untuk admin)"""
            data = request.json
            judul_edukasi = data.get('judul_edukasi')
            deskripsi_edukasi = data.get('deskripsi_edukasi')
            gambar = data.get('gambar')
            
            if not judul_edukasi or not deskripsi_edukasi:
                return jsonify({
                    'success': False,
                    'message': 'Judul dan deskripsi edukasi diperlukan'
                }), 400
            
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO edukasi (judul_edukasi, deskripsi_edukasi, gambar) VALUES (%s, %s, %s)",
                (judul_edukasi, deskripsi_edukasi, gambar)
            )
            mysql.connection.commit()
            
            new_content_id = cur.lastrowid
            cur.execute("SELECT * FROM edukasi WHERE id_edukasi = %s", [new_content_id])
            new_content = cur.fetchone()
            cur.close()
            
            return jsonify({
                'success': True,
                'message': 'Konten edukasi berhasil dibuat',
                'data': new_content
            }), 201
    except Exception as e:
        logging.error(f"Education contents error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Terjadi kesalahan: {str(e)}'
        }), 500

@app.route('/api/waste-education/<int:content_id>', methods=['GET', 'PUT', 'DELETE'])
def education_content(content_id):
    try:
        if request.method == 'GET':
            """Mendapatkan konten edukasi berdasarkan ID"""
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM edukasi WHERE id_edukasi = %s", [content_id])
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
            
        elif request.method == 'PUT':
            """Memperbarui konten edukasi (untuk admin)"""
            data = request.json
            judul_edukasi = data.get('judul_edukasi')
            deskripsi_edukasi = data.get('deskripsi_edukasi')
            gambar = data.get('gambar')
            
            cur = mysql.connection.cursor()
            
            # Periksa apakah konten ada
            cur.execute("SELECT * FROM edukasi WHERE id_edukasi = %s", [content_id])
            existing_content = cur.fetchone()
            
            if not existing_content:
                cur.close()
                return jsonify({
                    'success': False,
                    'message': 'Konten edukasi tidak ditemukan'
                }), 404
            
            # Update konten
            cur.execute(
                "UPDATE edukasi SET judul_edukasi = %s, deskripsi_edukasi = %s, gambar = %s WHERE id_edukasi = %s",
                (judul_edukasi, deskripsi_edukasi, gambar, content_id)
            )
            mysql.connection.commit()
            
            # Ambil data yang sudah diupdate
            cur.execute("SELECT * FROM edukasi WHERE id_edukasi = %s", [content_id])
            updated_content = cur.fetchone()
            cur.close()
            
            return jsonify({
                'success': True,
                'message': 'Konten edukasi berhasil diperbarui',
                'data': updated_content
            }), 200
            
        elif request.method == 'DELETE':
            """Menghapus konten edukasi (untuk admin)"""
            cur = mysql.connection.cursor()
            
            # Periksa apakah konten ada
            cur.execute("SELECT * FROM edukasi WHERE id_edukasi = %s", [content_id])
            existing_content = cur.fetchone()
            
            if not existing_content:
                cur.close()
                return jsonify({
                    'success': False,
                    'message': 'Konten edukasi tidak ditemukan'
                }), 404
            
            # Hapus konten
            cur.execute("DELETE FROM edukasi WHERE id_edukasi = %s", [content_id])
            mysql.connection.commit()
            cur.close()
            
            return jsonify({
                'success': True,
                'message': 'Konten edukasi berhasil dihapus'
            }), 200
    except Exception as e:
        logging.error(f"Education content error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Terjadi kesalahan: {str(e)}'
        }), 500

# --- HISTORY ENDPOINTS ---

@app.route('/api/history/waste', methods=['GET', 'POST'])
@jwt_required()
def history_waste():
    try:
        current_user_id = get_jwt_identity()
        
        if request.method == 'GET':
            """Mendapatkan history buang sampah user"""
            cur = mysql.connection.cursor()
            cur.execute("""
                SELECT hbs.*, s.nama_sampah, ks.jenis_sampah 
                FROM history_buang_sampah hbs
                JOIN sampah s ON hbs.id_sampah = s.id_sampah
                JOIN kategori_sampah ks ON hbs.id_kategori = ks.id_kategori
                WHERE hbs.id_users = %s 
                ORDER BY hbs.waktu DESC
            """, [current_user_id])
            history = cur.fetchall()
            cur.close()
            
            return jsonify(history), 200
            
        elif request.method == 'POST':
            """Menambahkan history buang sampah"""
            data = request.json
            waste_id = data.get('waste_id')
            category_id = data.get('category_id')
            jumlah = data.get('jumlah', 1)
            
            if not waste_id or not category_id:
                return jsonify({'message': 'Waste ID dan Category ID diperlukan'}), 400
            
            cur = mysql.connection.cursor()
            
            try:
                cur.execute(
                    "INSERT INTO history_buang_sampah (id_users, id_sampah, id_kategori, jumlah, tanggal, waktu) VALUES (%s, %s, %s, %s, CURDATE(), NOW())",
                    (current_user_id, waste_id, category_id, jumlah)
                )
                mysql.connection.commit()
                
                history_id = cur.lastrowid
                cur.close()
                
                return jsonify({
                    'message': 'History buang sampah berhasil dicatat',
                    'history_id': history_id
                }), 201
            except Exception as e:
                logging.error(f"Add history error: {str(e)}")
                cur.close()
                return jsonify({'message': 'Error saat mencatat history: ' + str(e)}), 500
    except Exception as e:
        logging.error(f"History waste error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan pada history endpoint'}), 500

# --- LEVEL ENDPOINTS ---

@app.route('/api/levels', methods=['GET'])
def get_levels():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM level_user ORDER BY point_min ASC")
        levels = cur.fetchall()
        cur.close()
        
        return jsonify(levels), 200
    except Exception as e:
        logging.error(f"Get levels error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil level'}), 500

@app.route('/api/users/level', methods=['GET'])
@jwt_required()
def get_user_level():
    try:
        current_user_id = get_jwt_identity()
        
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT u.current_level, l.nama_level, l.point_min, l.point_max
            FROM users u
            JOIN level_user l ON u.current_level = l.id_level
            WHERE u.id_users = %s
        """, [current_user_id])
        level_info = cur.fetchone()
        cur.close()
        
        if not level_info:
            return jsonify({'message': 'User level tidak ditemukan'}), 404
        
        return jsonify(level_info), 200
    except Exception as e:
        logging.error(f"Get user level error: {str(e)}")
        return jsonify({'message': 'Terjadi kesalahan saat mengambil level user'}), 500

@app.route('/cek-koneksi')
def cek_koneksi():
    try:
        cur = mysql.connection.cursor()
        cur.execute('SELECT 1')
        cur.close()
        return jsonify({'status': 'sukses', 'message': 'Database MySQL berhasil terkoneksi!'})
    except Exception as e:
        logging.error(f"Database connection error: {str(e)}")
        return jsonify({'status': 'gagal', 'message': str(e)}), 500

# --- 4. Jalankan Server ---
if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
