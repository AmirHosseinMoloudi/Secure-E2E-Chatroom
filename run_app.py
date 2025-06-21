#!/usr/bin/env python3
"""
Secure Chat Application Setup and Run Script
"""

import subprocess
import sys
import os

def install_requirements():
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("✗ Failed to install dependencies")
        return False
    return True

def run_app():
    """Run the Flask application"""
    print("\n" + "="*50)
    print("🚀 Starting Secure Chat Application")
    print("="*50)
    print("Features:")
    print("- End-to-End AES-256 Encryption")
    print("- Secure WebSocket Communication")
    print("- Multiple Chat Rooms")
    print("- Real-time Messaging")
    print("- SRI & Security Headers")
    print("- Ready for Native Client Development")
    print("="*50)
    print("Access the application at: http://localhost:5000")
    print("Default admin credentials: admin / admin123")
    print("="*50)
    
    try:
        from app import app, socketio
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except ImportError as e:
        print(f"✗ Failed to import app: {e}")
        return False
    except Exception as e:
        print(f"✗ Failed to start app: {e}")
        return False

if __name__ == "__main__":
    print("🔐 Secure Chat Application Setup")
    print("===============================")
    
    # Check if requirements.txt exists
    if not os.path.exists("requirements.txt"):
        print("✗ requirements.txt not found")
        sys.exit(1)
    
    # Install dependencies
    if not install_requirements():
        sys.exit(1)
    
    
    # Run the application
    run_app() 