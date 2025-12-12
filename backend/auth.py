"""Authentication module for Security Hardening API."""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from fastapi import HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from database import db

# API Key Header
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

class AuthManager:
    """Quản lý API keys và authentication."""
    
    def __init__(self):
        self.db = db
        self.api_keys_collection = self.db.db["api_keys"]
    
    def generate_api_key(self, name: str, description: str = "", expires_days: Optional[int] = None) -> dict:
        """Tạo API key mới."""
        # Generate random API key
        api_key = f"sk_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Tính expiration date
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        # Lưu vào database
        key_data = {
            "name": name,
            "description": description,
            "api_key_hash": api_key_hash,
            "created_at": datetime.utcnow(),
            "expires_at": expires_at,
            "is_active": True,
            "last_used": None,
            "usage_count": 0
        }
        
        self.api_keys_collection.insert_one(key_data)
        
        # Trả về API key (chỉ hiển thị lần này)
        return {
            "api_key": api_key,
            "name": name,
            "description": description,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_at": key_data["created_at"].isoformat(),
            "warning": "⚠️ Lưu API key này ngay! Bạn sẽ không thể xem lại sau khi rời trang này."
        }
    
    def verify_api_key(self, api_key: Optional[str]) -> bool:
        """Xác thực API key."""
        if not api_key:
            return False
        
        # Hash API key để so sánh
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Tìm trong database
        key_doc = self.api_keys_collection.find_one({"api_key_hash": api_key_hash, "is_active": True})
        
        if not key_doc:
            return False
        
        # Kiểm tra expiration
        if key_doc.get("expires_at") and datetime.utcnow() > key_doc["expires_at"]:
            return False
        
        # Cập nhật last_used và usage_count
        self.api_keys_collection.update_one(
            {"_id": key_doc["_id"]},
            {
                "$set": {"last_used": datetime.utcnow()},
                "$inc": {"usage_count": 1}
            }
        )
        
        return True
    
    def revoke_api_key(self, api_key_hash: str) -> bool:
        """Vô hiệu hóa API key."""
        result = self.api_keys_collection.update_one(
            {"api_key_hash": api_key_hash},
            {"$set": {"is_active": False, "revoked_at": datetime.utcnow()}}
        )
        return result.modified_count > 0
    
    def list_api_keys(self) -> list:
        """Lấy danh sách API keys (không hiển thị hash)."""
        keys = list(self.api_keys_collection.find({}, {"api_key_hash": 0}).sort("created_at", -1))
        for key in keys:
            key["_id"] = str(key["_id"])
            if key.get("created_at"):
                key["created_at"] = key["created_at"].isoformat()
            if key.get("expires_at"):
                key["expires_at"] = key["expires_at"].isoformat()
            if key.get("last_used"):
                key["last_used"] = key["last_used"].isoformat()
            if key.get("revoked_at"):
                key["revoked_at"] = key["revoked_at"].isoformat()
        return keys
    
    def has_any_active_keys(self) -> bool:
        """Kiểm tra xem có API key nào active không."""
        count = self.api_keys_collection.count_documents({"is_active": True})
        return count > 0
    
    def delete_all_api_keys(self) -> int:
        """Xóa tất cả API keys (dùng để reset)."""
        result = self.api_keys_collection.delete_many({})
        return result.deleted_count
    
    def delete_api_key_by_hash(self, api_key_hash: str) -> bool:
        """Xóa API key theo hash (xóa hoàn toàn, không chỉ revoke)."""
        result = self.api_keys_collection.delete_one({"api_key_hash": api_key_hash})
        return result.deleted_count > 0

# Global instance
auth_manager = AuthManager()

async def verify_api_key(api_key: Optional[str] = Security(API_KEY_HEADER)) -> bool:
    """Dependency để verify API key."""
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Please provide X-API-Key header."
        )
    
    if not auth_manager.verify_api_key(api_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key."
        )
    
    return True

# Dependency để protect endpoints
RequireAuth = Depends(verify_api_key)

