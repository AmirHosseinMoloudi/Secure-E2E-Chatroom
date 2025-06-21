#!/usr/bin/env python3
"""
Test script to check room creation and retrieval
"""

import sys
import os

# Add the current directory to the path so we can import our app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db, Room, User

def test_rooms():
    with app.app_context():
        # Check if database exists and has tables
        try:
            db.create_all()
            print("✓ Database tables created/verified")
        except Exception as e:
            print(f"✗ Database error: {e}")
            return
        
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print(f"✓ Admin user exists: {admin.username}")
        else:
            print("✗ Admin user not found")
            return
        
        # Check existing rooms
        rooms = Room.query.all()
        print(f"📁 Found {len(rooms)} rooms:")
        
        for room in rooms:
            creator = db.session.get(User, room.created_by)
            print(f"  - Room: {room.name}")
            print(f"    ID: {room.id}")
            print(f"    Description: {room.description}")
            print(f"    Created by: {creator.username if creator else 'Unknown'}")
            print(f"    Created at: {room.created_at}")
            print()
        
        # Test API endpoint simulation
        print("🔧 Testing room data format:")
        rooms_data = []
        for room in rooms:
            creator = db.session.get(User, room.created_by)
            room_data = {
                'id': room.id,
                'name': room.name,
                'description': room.description,
                'created_by': creator.username if creator else 'Unknown',
                'created_at': room.created_at.isoformat(),
                'is_private': room.is_private
            }
            rooms_data.append(room_data)
            print(f"  Room data: {room_data}")
        
        print(f"\n✅ Room API would return: {len(rooms_data)} rooms")

if __name__ == "__main__":
    test_rooms() 