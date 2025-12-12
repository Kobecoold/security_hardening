#!/usr/bin/env python3
"""
Script để xóa tất cả API keys từ MongoDB.
Sử dụng khi cần reset authentication hoàn toàn.

Usage:
    python scripts/clear-api-keys.py
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from database import db

def clear_all_api_keys():
    """Xóa tất cả API keys từ MongoDB."""
    try:
        api_keys_collection = db.db["api_keys"]
        
        # Đếm số keys hiện có
        count_before = api_keys_collection.count_documents({})
        
        if count_before == 0:
            print("ℹ️  Không có API key nào trong database.")
            return
        
        # Xác nhận
        print(f"⚠️  CẢNH BÁO: Bạn sắp xóa {count_before} API key(s)!")
        confirm = input("Nhập 'YES' để xác nhận: ")
        
        if confirm != "YES":
            print("❌ Đã hủy. Không có API key nào bị xóa.")
            return
        
        # Xóa tất cả
        result = api_keys_collection.delete_many({})
        
        print(f"✅ Đã xóa {result.deleted_count} API key(s) thành công!")
        print("💡 Bây giờ bạn có thể tạo API key mới qua endpoint /auth/setup")
        
    except Exception as e:
        print(f"❌ Lỗi: {e}")
        sys.exit(1)

if __name__ == "__main__":
    clear_all_api_keys()

