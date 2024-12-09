from flask import Flask, jsonify, request
import sqlite3
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import jwt
import base64
import os
import uuid
import time
from argon2 import PasswordHasher
from collections import defaultdict
import threading

app = Flask(__name__)
DB_NAME = "totally_not_my_privateKeys.db"
SHARED_SECRET = "your-256-bit-secret"
KID = "fixed-kid-for-hs256"

# Fixed encryption key for testing
FIXED_KEY = base64.b64encode(b'mysupersecretkey12345mysupersecret12').decode()
NOT_MY_KEY = os.environ.get('NOT_MY_KEY', FIXED_KEY)

# Rate limiting setup
RATE_LIMIT = 10
rate_limit_data = defaultdict(list)
rate_limit_lock = threading.Lock()

def initialize_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )""")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    
    conn.commit()
    conn.close()

def encrypt_key(key_data):
    key = base64.b64decode(FIXED_KEY)[:32]
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = key_data + b'\0' * (-len(key_data) % 16)
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_key(encrypted_data):
    key = base64.b64decode(FIXED_KEY)[:32]
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted.rstrip(b'\0')

def generate_and_store_key(expiration_in_hours):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Encrypt the key before storing
    encrypted_key = encrypt_key(pem_key)
    
    expiration = datetime.utcnow() + timedelta(hours=expiration_in_hours)
    exp_timestamp = int(expiration.timestamp())
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, exp_timestamp))
    conn.commit()
    conn.close()

def check_rate_limit(ip):
    with rate_limit_lock:
        now = time.time()
        requests = rate_limit_data[ip]
        requests = [req for req in requests if now - req < 1.0]
        rate_limit_data[ip] = requests
        
        if len(requests) >= RATE_LIMIT:
            return False
        
        rate_limit_data[ip].append(now)
        return True

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({'error': 'Missing required fields'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        password = str(uuid.uuid4())
        ph = PasswordHasher()
        password_hash = ph.hash(password)
        
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (data['username'], password_hash, data['email'])
        )
        conn.commit()
        return jsonify({'password': password}), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username or email already exists'}), 409
    finally:
        conn.close()

@app.route('/auth', methods=['POST'])
def auth():
    if not check_rate_limit(request.remote_addr):
        return jsonify({'error': 'Too many requests'}), 429

    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Missing credentials'}), 400
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (data['username'],))
        user = cursor.fetchone()
        
        if user:
            ph = PasswordHasher()
            try:
                ph.verify(user[1], data['password'])
                
                # Log successful auth
                cursor.execute(
                    "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
                    (request.remote_addr, user[0])
                )
                conn.commit()
                
                # Generate JWT
                expired = request.args.get('expired', 'false').lower() == 'true'
                exp_time = datetime.utcnow() - timedelta(minutes=1) if expired else datetime.utcnow() + timedelta(minutes=30)
                
                token = jwt.encode(
                    {'user_id': user[0], 'exp': exp_time},
                    SHARED_SECRET,
                    algorithm='HS256',
                    headers={'kid': KID}
                )
                
                return jsonify({'token': token})
            except Exception:
                return jsonify({'error': 'Invalid credentials'}), 401
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    finally:
        conn.close()

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwk = {
        "kid": KID,
        "kty": "oct",
        "alg": "HS256",
        "use": "sig",
        "k": base64.urlsafe_b64encode(SHARED_SECRET.encode()).decode('utf-8').rstrip("=")
    }
    return jsonify({"keys": [jwk]})

if __name__ == "__main__":
    initialize_database()
    # Generate both expired and valid keys
    generate_and_store_key(-1)  # Expired key
    generate_and_store_key(1)   # Valid key
    app.run(host='127.0.0.1', port=8080)