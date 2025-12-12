"""User management module for Security Hardening API."""
import hashlib
import secrets
from datetime import datetime
from typing import Optional, Dict
from fastapi import HTTPException
from database import db

class UserManager:
    """Quản lý users và authentication."""
    
    def __init__(self):
        self.db = db
        self.users_collection = self.db.db["users"]
    
    def create_user(self, username: str, password: str, email: str = "", role: str = "user") -> Dict:
        """Tạo user mới."""
        # Check if user exists
        if self.users_collection.find_one({"username": username}):
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user_data = {
            "username": username,
            "password_hash": password_hash,
            "email": email,
            "role": role,
            "created_at": datetime.utcnow(),
            "is_active": True,
            "last_login": None
        }
        
        self.users_collection.insert_one(user_data)
        
        return {
            "username": username,
            "email": email,
            "role": role,
            "created_at": user_data["created_at"].isoformat()
        }
    
    def verify_user(self, username: str, password: str) -> bool:
        """Xác thực user."""
        user = self.users_collection.find_one({"username": username, "is_active": True})
        
        if not user:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if user["password_hash"] != password_hash:
            return False
        
        # Update last_login
        self.users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return True
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Lấy thông tin user."""
        user = self.users_collection.find_one({"username": username})
        if user:
            user["_id"] = str(user["_id"])
            del user["password_hash"]
            if user.get("created_at"):
                user["created_at"] = user["created_at"].isoformat()
            if user.get("last_login"):
                user["last_login"] = user["last_login"].isoformat()
        return user
    
    def has_any_users(self) -> bool:
        """Kiểm tra xem có user nào không."""
        count = self.users_collection.count_documents({})
        return count > 0

# Global instance
user_manager = UserManager()

