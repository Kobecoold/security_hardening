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
    
    def get_user_by_api_key_name(self, api_key_name: str) -> Optional[Dict]:
        """Lấy user từ API key name (format: "User: username")."""
        if not api_key_name or not api_key_name.startswith("User: "):
            return None
        username = api_key_name.replace("User: ", "").strip()
        return self.get_user(username)
    
    def list_users(self) -> list:
        """Lấy danh sách tất cả users."""
        users = list(self.users_collection.find({}, {"password_hash": 0}).sort("created_at", -1))
        for user in users:
            user["_id"] = str(user["_id"])
            if user.get("created_at"):
                user["created_at"] = user["created_at"].isoformat()
            if user.get("last_login"):
                user["last_login"] = user["last_login"].isoformat()
        return users
    
    def update_user(self, username: str, email: Optional[str] = None, password: Optional[str] = None) -> Dict:
        """Cập nhật thông tin user."""
        user = self.users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        update_data = {}
        if email is not None:
            update_data["email"] = email
        if password is not None:
            update_data["password_hash"] = hashlib.sha256(password.encode()).hexdigest()
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        self.users_collection.update_one(
            {"username": username},
            {"$set": update_data}
        )
        
        return self.get_user(username)
    
    def delete_user(self, username: str) -> bool:
        """Xóa user (soft delete - set is_active = False)."""
        user = self.users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Không cho phép xóa admin cuối cùng
        if user.get("role") == "admin":
            admin_count = self.users_collection.count_documents({"role": "admin", "is_active": True})
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="Cannot delete the last admin user")
        
        # Soft delete
        self.users_collection.update_one(
            {"username": username},
            {"$set": {"is_active": False}}
        )
        
        return True
    
    def change_role(self, username: str, new_role: str) -> Dict:
        """Thay đổi role của user."""
        if new_role not in ["admin", "user"]:
            raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'user'")
        
        user = self.users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        current_role = user.get("role")
        
        # Không cho phép tạo thêm admin (chỉ có 1 admin)
        if new_role == "admin" and current_role != "admin":
            admin_count = self.users_collection.count_documents({"role": "admin", "is_active": True})
            if admin_count >= 1:
                raise HTTPException(status_code=400, detail="Cannot create additional admin users. Only one admin account is allowed.")
        
        # Không cho phép xóa admin cuối cùng
        if current_role == "admin" and new_role == "user":
            admin_count = self.users_collection.count_documents({"role": "admin", "is_active": True})
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="Cannot remove admin role from the last admin user")
        
        self.users_collection.update_one(
            {"username": username},
            {"$set": {"role": new_role}}
        )
        
        return self.get_user(username)

# Global instance
user_manager = UserManager()

