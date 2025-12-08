"""MongoDB database module for security hardening audit engine."""
from pymongo import MongoClient
from datetime import datetime
import uuid
from typing import Dict, List, Optional

class AuditDB:
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        """
        Kết nối đến MongoDB Docker container.
        """
        try:
            self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            print("✅ Connected to MongoDB Docker container successfully!")
            
            self.db = self.client["security_hardening"]
            self.audits = self.db["audit_reports"]
            self.remediations = self.db["remediation_logs"] 
            self.backups = self.db["system_backups"]  # THÊM COLLECTION BACKUPS
            
            # Kiểm tra collections
            print(f"✅ Collections: {self.db.list_collection_names()}")
            
        except Exception as e:
            print(f"❌ MongoDB connection failed: {e}")
            print("💡 Kiểm tra: docker ps | grep mongodb")
            raise
    
    def save_backup(self, backup_data: Dict) -> str:
        """Lưu backup vào MongoDB collection system_backups."""
        try:
            backup_id = str(uuid.uuid4())
            backup_data["_id"] = backup_id
            backup_data["backup_id"] = backup_id
            backup_data["created_at"] = datetime.utcnow()
            
            self.backups.insert_one(backup_data)
            print(f"✅ Backup saved to MongoDB: {backup_id}")
            return backup_id
        except Exception as e:
            print(f"❌ Failed to save backup: {e}")
            raise
    
    def get_backups_by_host(self, host: str, limit: int = 10) -> List[Dict]:
        """Lấy danh sách backups của một host."""
        return list(self.backups.find({"host": host}).sort("created_at", -1).limit(limit))
    
    def get_latest_backup(self, host: str) -> Optional[Dict]:
        """Lấy backup mới nhất của host."""
        return self.backups.find_one({"host": host, "type": "pre_remediation_backup"}, sort=[("created_at", -1)])
    
    def save_audit_report(self, audit_data: Dict) -> str:
        """Lưu kết quả audit vào MongoDB"""
        audit_id = str(uuid.uuid4())
        audit_data["_id"] = audit_id
        audit_data["created_at"] = datetime.utcnow()
        audit_data["audit_id"] = audit_id
        
        # Tính toán compliance score
        total_rules = len(audit_data.get("results", []))
        passed_rules = sum(1 for r in audit_data.get("results", []) if r.get("status") == "PASS")
        audit_data["compliance_score"] = round((passed_rules / total_rules * 100), 2) if total_rules > 0 else 0
        
        self.audits.insert_one(audit_data)
        print(f"✅ Audit report saved to MongoDB: {audit_id}")
        return audit_id
    
    def save_remediation_log(self, remediation_data: Dict) -> str:
        """Lưu log remediation vào MongoDB"""
        remediation_id = str(uuid.uuid4())
        remediation_data["_id"] = remediation_id
        remediation_data["remediation_id"] = remediation_id
        remediation_data["created_at"] = datetime.utcnow()
        
        self.remediations.insert_one(remediation_data)
        print(f"✅ Remediation log saved to MongoDB: {remediation_id}")
        return remediation_id
    
    def get_audit_reports(self, host: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Lấy danh sách audit reports"""
        query = {}
        if host:
            query["host"] = host
        
        return list(self.audits.find(query).sort("created_at", -1).limit(limit))
    
    def get_remediation_logs(self, host: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Lấy danh sách remediation logs"""
        query = {}
        if host:
            query["host"] = host
        
        return list(self.remediations.find(query).sort("created_at", -1).limit(limit))
    
    def get_hosts_overview(self) -> List[Dict]:
        """Lấy overview của tất cả hosts"""
        pipeline = [
            {"$sort": {"created_at": -1}},
            {"$group": {
                "_id": "$host",
                "latest_audit": {"$first": "$$ROOT"},
                "audit_count": {"$sum": 1},
                "os_type": {"$first": "$os_type"}
            }},
            {"$project": {
                "host": "$_id",
                "os_type": 1,
                "latest_audit_time": "$latest_audit.created_at",
                "compliance_score": "$latest_audit.compliance_score",
                "total_rules": "$latest_audit.total_rules",
                "passed_rules": {"$size": {"$filter": {
                    "input": "$latest_audit.results",
                    "as": "result",
                    "cond": {"$eq": ["$$result.status", "PASS"]}
                }}},
                "audit_count": 1
            }}
        ]
        return list(self.audits.aggregate(pipeline))
    
    def get_compliance_stats(self) -> Dict:
        """Thống kê compliance tổng thể"""
        pipeline = [
            {"$group": {
                "_id": "$os_type",
                "avg_compliance": {"$avg": "$compliance_score"},
                "total_audits": {"$sum": 1},
                "unique_hosts": {"$addToSet": "$host"}
            }}
        ]
        
        stats = list(self.audits.aggregate(pipeline))
        overall_avg = sum(s["avg_compliance"] for s in stats) / len(stats) if stats else 0
        
        return {
            "by_os": stats,
            "overall_avg_compliance": round(overall_avg, 2)
        }

# Kết nối đến MongoDB Docker container
db = AuditDB()
