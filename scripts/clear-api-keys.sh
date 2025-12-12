#!/bin/bash
# Script để xóa tất cả API keys từ MongoDB (sử dụng mongosh)

echo "⚠️  CẢNH BÁO: Script này sẽ xóa TẤT CẢ API keys từ MongoDB!"
read -p "Nhập 'YES' để xác nhận: " confirm

if [ "$confirm" != "YES" ]; then
    echo "❌ Đã hủy. Không có API key nào bị xóa."
    exit 0
fi

# Xóa tất cả API keys
docker compose exec -T mongodb mongosh security_hardening --quiet --eval "
db.api_keys.deleteMany({})
"

if [ $? -eq 0 ]; then
    echo "✅ Đã xóa tất cả API keys thành công!"
    echo "💡 Bây giờ bạn có thể tạo API key mới qua endpoint /auth/setup"
else
    echo "❌ Lỗi khi xóa API keys"
    exit 1
fi

