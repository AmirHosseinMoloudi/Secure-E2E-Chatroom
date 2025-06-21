# 🔐 Secure Chat - The Most Encrypted Chatroom

A highly secure, end-to-end encrypted chatroom built with Flask and AES-256 encryption. This application provides security that protects your communications.

## 🛡️ Security Features

### End-to-End Encryption

- **AES-256-GCM** encryption for all messages
- **Client-side encryption** - server never sees plaintext
- **Perfect Forward Secrecy** with ephemeral keys
- **Message integrity** verification with SHA-256 hashing

### Transport Security

- **HTTPS/WSS** mandatory for all connections
- **HSTS** (HTTP Strict Transport Security) enabled
- **Certificate pinning** support
- **TLS 1.3** recommended

### Application Security

- **CSP** (Content Security Policy) with strict directives
- **SRI** (Subresource Integrity) for all external resources
- **XSS** and **CSRF** protection
- **Security headers** (X-Frame-Options, X-Content-Type-Options, etc.)
- **PBKDF2** password hashing with 100,000 iterations

### Privacy Protection

- **No logging** of message content
- **Encrypted storage** of all sensitive data
- **Memory-safe** operations
- **Secure session management**

## 🚀 Quick Start

1. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**

   ```bash
   python app.py
   ```

3. **Access the Application**

   ```
   http://localhost:5000
   ```

4. **Default Admin Account**
   ```
   Username: admin
   Password: admin123
   ```

## 📱 Native Client Development

The application is designed to support native clients through its REST API and WebSocket endpoints:

### REST API Endpoints

- `POST /login` - User authentication
- `POST /register` - User registration
- `GET /api/rooms` - Get room list
- `POST /api/rooms` - Create new room

### WebSocket Events

- `connect` - Establish connection
- `join_room` - Join a chat room
- `send_message` - Send encrypted message
- `new_message` - Receive encrypted message
- `room_history` - Get message history

### Example Native Client Integration

```javascript
// Connect to WebSocket
const socket = io("wss://your-server.com");

// Encrypt message before sending
const encrypted = await crypto.subtle.encrypt(
  { name: "AES-GCM", iv: iv },
  key,
  messageData
);

socket.emit("send_message", {
  room_id: roomId,
  encrypted_content: JSON.stringify(Array.from(new Uint8Array(encrypted))),
  iv: JSON.stringify(Array.from(iv)),
  message_hash: await hashMessage(message),
});
```

## 🔧 Configuration

### Environment Variables

```bash
# Security
SECRET_KEY=your-secret-key-here
FLASK_ENV=production

# Database
DATABASE_URL=sqlite:///secure_chat.db

# SSL/TLS (Production)
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

### Production Deployment

```bash
# Install production dependencies
pip install gunicorn eventlet

# Run with Gunicorn
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app

# Or with SSL
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:443 \
    --certfile=cert.pem --keyfile=key.pem app:app
```

## 🏗️ Architecture

### Frontend Security

- **Web Crypto API** for client-side encryption
- **Subresource Integrity** for all external resources
- **Content Security Policy** prevents XSS attacks
- **Secure contexts** (HTTPS) required for crypto operations

### Backend Security

- **Flask-SocketIO** for real-time communication
- **Bcrypt** for password hashing
- **SQLAlchemy** with parameterized queries
- **CSRF protection** on all forms
- **Rate limiting** to prevent abuse

### Encryption Process

```
1. User types message
2. Generate random IV (Initialization Vector)
3. Encrypt message with AES-256-GCM + room key
4. Hash message for integrity verification
5. Send encrypted data to server
6. Server stores encrypted data (never sees plaintext)
7. Server broadcasts encrypted data to room members
8. Recipients decrypt message with shared room key
```

## 🔒 Security Best Practices

### For Developers

- Always use HTTPS in production
- Implement proper key management
- Regular security audits
- Keep dependencies updated
- Use strong random keys
- Implement proper error handling

### For Users

- Use strong, unique passwords
- Enable 2FA if available
- Keep browser updated
- Use trusted networks
- Verify SSL certificates
- Be cautious with file sharing

## 🛠️ Development

### Local Development

```bash
# Clone repository
git clone <repository-url>
cd secure-chat

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_ENV=development
export SECRET_KEY=dev-key-change-in-production

# Run application
python app.py
```

### Testing

```bash
# Run tests
python -m pytest tests/

# Security tests
python -m pytest tests/security/

# Load testing
python -m pytest tests/load/
```

## 📚 API Documentation

### Authentication

All API endpoints require authentication via session cookies or JWT tokens.

### Message Format

```json
{
  "room_id": 1,
  "encrypted_content": "[1,2,3,4,5...]",
  "iv": "[6,7,8,9,10...]",
  "message_hash": "sha256-hash-of-original-message",
  "timestamp": "2023-12-01T12:00:00Z"
}
```

### Error Responses

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2023-12-01T12:00:00Z"
}
```

## 🔐 Cryptographic Details

### Encryption Algorithm

- **Algorithm**: AES-256-GCM
- **Key Size**: 256 bits
- **IV Size**: 96 bits (12 bytes)
- **Authentication**: Built-in AEAD

### Key Derivation

- **Algorithm**: PBKDF2-SHA256
- **Iterations**: 100,000
- **Salt**: Random 128-bit
- **Output**: 256-bit key

### Message Integrity

- **Algorithm**: SHA-256
- **Input**: Original plaintext message
- **Output**: 256-bit hash

## 🚨 Security Considerations

### Threat Model

- **ISP/VPS Surveillance**: ✅ Protected
- **Man-in-the-Middle**: ✅ Protected (with proper TLS)
- **Server Compromise**: ✅ Messages remain encrypted
- **Database Breach**: ✅ No plaintext data stored
- **Client-side Attacks**: ⚠️ Requires user education

### Limitations

- Requires JavaScript enabled
- Vulnerable to client-side malware
- Metadata (timestamps, room membership) not encrypted
- No forward secrecy between sessions

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

**⚠️ Security Notice**: This application is designed for educational and legitimate use only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.
