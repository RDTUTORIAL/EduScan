"""
Simple JSON-based database for EduScan history management.
Uses file-based storage with user identification via cookies.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib

# Database configuration
DB_DIR = Path(__file__).parent / "data"
USERS_FILE = DB_DIR / "users.json"
HISTORY_DIR = DB_DIR / "history"

# Ensure directories exist
DB_DIR.mkdir(exist_ok=True)
HISTORY_DIR.mkdir(exist_ok=True)

class DatabaseManager:
    def __init__(self):
        self._ensure_db_files()
    
    def _ensure_db_files(self):
        """Ensure database files exist with proper structure."""
        if not USERS_FILE.exists():
            USERS_FILE.write_text(json.dumps({}))
    
    def _get_user_file(self, user_id: str) -> Path:
        """Get the file path for a user's history."""
        return HISTORY_DIR / f"{user_id}.json"
    
    def _read_json(self, file_path: Path) -> Dict:
        """Safely read JSON file."""
        try:
            if file_path.exists():
                return json.loads(file_path.read_text())
            return {}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _write_json(self, file_path: Path, data: Dict):
        """Safely write JSON file."""
        file_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    
    def create_user(self) -> str:
        """Create a new user and return user ID."""
        user_id = str(uuid.uuid4())
        users = self._read_json(USERS_FILE)
        
        users[user_id] = {
            "created_at": datetime.utcnow().isoformat(),
            "last_active": datetime.utcnow().isoformat(),
            "scan_count": 0
        }
        
        self._write_json(USERS_FILE, users)
        
        # Initialize empty history
        user_file = self._get_user_file(user_id)
        self._write_json(user_file, {"history": []})
        
        return user_id
    
    def get_user(self, user_id: str) -> Optional[Dict]:
        """Get user information."""
        users = self._read_json(USERS_FILE)
        return users.get(user_id)
    
    def update_user_activity(self, user_id: str):
        """Update user's last activity timestamp."""
        users = self._read_json(USERS_FILE)
        if user_id in users:
            users[user_id]["last_active"] = datetime.utcnow().isoformat()
            self._write_json(USERS_FILE, users)
    
    def add_history_entry(self, user_id: str, entry: Dict) -> Dict:
        """Add a scan history entry for a user."""
        user_file = self._get_user_file(user_id)
        data = self._read_json(user_file)
        
        if "history" not in data:
            data["history"] = []
        
        # Add timestamp and ensure ID exists
        entry_with_meta = {
            **entry,
            "id": entry.get("id", str(uuid.uuid4())),
            "timestamp": entry.get("timestamp", datetime.utcnow().isoformat()),
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Add to beginning of list
        data["history"].insert(0, entry_with_meta)
        
        # Keep only last 100 entries per user
        data["history"] = data["history"][:100]
        
        self._write_json(user_file, data)
        
        # Update user stats
        self._increment_user_scan_count(user_id)
        self.update_user_activity(user_id)
        
        return entry_with_meta
    
    def get_history(self, user_id: str, page: int = 1, per_page: int = 5) -> Dict:
        """Get paginated history for a user."""
        user_file = self._get_user_file(user_id)
        data = self._read_json(user_file)
        
        history = data.get("history", [])
        total = len(history)
        
        # Calculate pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        
        paginated_history = history[start_idx:end_idx]
        
        total_pages = (total + per_page - 1) // per_page
        
        return {
            "items": paginated_history,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        }
    
    def delete_history_entry(self, user_id: str, entry_id: str) -> bool:
        """Delete a specific history entry."""
        user_file = self._get_user_file(user_id)
        data = self._read_json(user_file)
        
        if "history" not in data:
            return False
        
        original_length = len(data["history"])
        data["history"] = [entry for entry in data["history"] if entry.get("id") != entry_id]
        
        if len(data["history"]) < original_length:
            self._write_json(user_file, data)
            self.update_user_activity(user_id)
            return True
        
        return False
    
    def clear_history(self, user_id: str) -> bool:
        """Clear all history for a user."""
        user_file = self._get_user_file(user_id)
        data = self._read_json(user_file)
        
        data["history"] = []
        self._write_json(user_file, data)
        self.update_user_activity(user_id)
        return True
    
    def _increment_user_scan_count(self, user_id: str):
        """Increment user's scan count."""
        users = self._read_json(USERS_FILE)
        if user_id in users:
            users[user_id]["scan_count"] = users[user_id].get("scan_count", 0) + 1
            self._write_json(USERS_FILE, users)
    
    def get_user_stats(self, user_id: str) -> Dict:
        """Get user statistics."""
        user_info = self.get_user(user_id)
        if not user_info:
            return {}
        
        user_file = self._get_user_file(user_id)
        data = self._read_json(user_file)
        history = data.get("history", [])
        
        # Calculate stats
        total_scans = len(history)
        tools_used = set(entry.get("tool", "Unknown") for entry in history)
        
        recent_scans = [entry for entry in history[:10]]  # Last 10 scans
        
        return {
            "user_id": user_id,
            "created_at": user_info.get("created_at"),
            "last_active": user_info.get("last_active"),
            "total_scans": total_scans,
            "tools_used": len(tools_used),
            "tools_list": list(tools_used),
            "recent_scans": recent_scans
        }

# Global database instance
db = DatabaseManager()
