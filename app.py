import os
import secrets
import hashlib
import base64
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app with security configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///secure_chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Security headers middleware
@app.after_request
def security_headers(response):
    # Strict Transport Security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Content Security Policy with SRI
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=True)  # For ECDH key exchange
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_private = db.Column(db.Boolean, default=False)
    room_key_hash = db.Column(db.String(128))  # Hashed room key for verification

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)  # Encrypted message
    iv = db.Column(db.String(32), nullable=False)  # Initialization vector
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message_hash = db.Column(db.String(128), nullable=False)  # For integrity

# Cryptographic utilities
class CryptoUtils:
    @staticmethod
    def generate_salt():
        return secrets.token_hex(16)
    
    @staticmethod
    def derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt_message(message, key):
        f = Fernet(key)
        return f.encrypt(message.encode())
    
    @staticmethod
    def decrypt_message(encrypted_message, key):
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()
    
    @staticmethod
    def hash_message(message):
        return hashlib.sha256(message.encode()).hexdigest()

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            # Update last seen
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'success': True, 'redirect': url_for('index')})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Validate input
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'})
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'})
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Registration successful'})
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/rooms')
def get_rooms():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    rooms = Room.query.all()
    rooms_data = []
    for room in rooms:
        creator = db.session.get(User, room.created_by)
        rooms_data.append({
            'id': room.id,
            'name': room.name,
            'description': room.description,
            'created_by': creator.username,
            'created_at': room.created_at.isoformat(),
            'is_private': room.is_private
        })
    
    return jsonify(rooms_data)

@app.route('/api/rooms', methods=['POST'])
def create_room():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    name = data.get('name')
    description = data.get('description', '')
    is_private = data.get('is_private', False)
    
    if not name:
        return jsonify({'error': 'Room name is required'}), 400
    
    if Room.query.filter_by(name=name).first():
        return jsonify({'error': 'Room name already exists'}), 400
    
    room = Room(
        name=name,
        description=description,
        created_by=session['user_id'],
        is_private=is_private
    )
    db.session.add(room)
    db.session.commit()
    
    return jsonify({'success': True, 'room_id': room.id})

# WebSocket events
@socketio.on('connect')
def on_connect():
    if 'user_id' not in session:
        return False
    
    user = db.session.get(User, session['user_id'])
    if user:
        user.last_seen = datetime.utcnow()
        db.session.commit()
    
    emit('connected', {'message': 'Connected to secure chat'})
    logger.info(f"User {session.get('username')} connected")

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f"User {session.get('username')} disconnected")

@socketio.on('join_room')
def on_join_room(data):
    if 'user_id' not in session:
        return
    
    room_id = data.get('room_id')
    room = db.session.get(Room, room_id)
    
    if not room:
        emit('error', {'message': 'Room not found'})
        return
    
    join_room(str(room_id))
    emit('joined_room', {
        'room_id': room_id,
        'room_name': room.name,
        'message': f"Joined room: {room.name}"
    })
    
    # Send recent messages (encrypted)
    recent_messages = Message.query.filter_by(room_id=room_id)\
                                 .order_by(Message.timestamp.desc())\
                                 .limit(50).all()
    
    messages_data = []
    for msg in reversed(recent_messages):
        user = db.session.get(User, msg.user_id)
        messages_data.append({
            'id': msg.id,
            'username': user.username,
            'encrypted_content': msg.encrypted_content,
            'iv': msg.iv,
            'timestamp': msg.timestamp.isoformat(),
            'message_hash': msg.message_hash
        })
    
    emit('room_history', {'messages': messages_data})

@socketio.on('leave_room')
def on_leave_room(data):
    room_id = data.get('room_id')
    leave_room(str(room_id))
    emit('left_room', {'room_id': room_id})

@socketio.on('send_message')
def on_send_message(data):
    if 'user_id' not in session:
        return
    
    room_id = data.get('room_id')
    encrypted_content = data.get('encrypted_content')
    iv = data.get('iv')
    message_hash = data.get('message_hash')
    
    if not all([room_id, encrypted_content, iv, message_hash]):
        emit('error', {'message': 'Invalid message data'})
        return
    
    # Verify room exists
    room = db.session.get(Room, room_id)
    if not room:
        emit('error', {'message': 'Room not found'})
        return
    
    # Store encrypted message
    message = Message(
        room_id=room_id,
        user_id=session['user_id'],
        encrypted_content=encrypted_content,
        iv=iv,
        message_hash=message_hash
    )
    db.session.add(message)
    db.session.commit()
    
    # Broadcast to room
    user = db.session.get(User, session['user_id'])
    socketio.emit('new_message', {
        'id': message.id,
        'username': user.username,
        'encrypted_content': encrypted_content,
        'iv': iv,
        'timestamp': message.timestamp.isoformat(),
        'message_hash': message_hash
    }, room=str(room_id))

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default room if it doesn't exist
    if not Room.query.filter_by(name='General').first():
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@securechat.local')
            admin.set_password('admin123')  # Change this in production
            db.session.add(admin)
            db.session.commit()
        
        general_room = Room(
            name='General',
            description='General discussion room',
            created_by=admin.id
        )
        db.session.add(general_room)
        db.session.commit()

if __name__ == '__main__':
        socketio.run(app, host='127.0.0.1', port=5000, debug=True)
    # Force HTTPS in production
    # socketio.run(app, host='0.0.0.0', port=5000, debug=False, ssl_context='adhoc' if os.environ.get('FLASK_ENV') == 'production' else None) 