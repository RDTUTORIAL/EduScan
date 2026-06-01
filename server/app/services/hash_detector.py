#!/usr/bin/env python3
"""
Enhanced Hash Detection Module
Based on hash-id.py patterns with improvements
"""

def detect_hash_type(hash_string: str) -> str:
    """
    Detect hash type based on patterns from hash-id.py
    Returns empty string if it's likely plaintext
    """
    if not hash_string:
        return ""
    
    h = hash_string.strip()
    
    # Quick plaintext detection - if it has spaces or common password chars and isn't hex
    if ' ' in h or (any(c in h for c in ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '?', '<', '>', ',', '.', ';', ':', '"', "'", '`', '~']) and len(h) < 64):
        # Check if it's still a valid hex hash despite special chars
        if not (len(h) in [16, 32, 40, 56, 64, 80, 96, 128] and all(c in "0123456789abcdefABCDEF" for c in h)):
            return ""
    
    # Structured hash formats (highest priority)
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$") or h.startswith("$2x$"):
        return "bcrypt"
    
    if h.startswith("$1$") and len(h) >= 30:
        return "MD5crypt"
    
    if h.startswith("$6$") and len(h) >= 90:
        return "SHA512crypt"
    
    if h.startswith("$5$") and len(h) >= 60:
        return "SHA256crypt"
    
    if h.startswith("$P$") and len(h) == 34:
        return "WordPress"
    
    if h.startswith("$H$") and len(h) == 34:
        return "phpBB3"
    
    if h.startswith("$apr1$") and len(h) >= 30:
        return "Apache MD5"
    
    # MySQL formats
    if h.startswith("*") and len(h) == 41:
        return "MySQL5"
    
    # Hex-based detection (case insensitive)
    h_lower = h.lower()
    if all(c in "0123456789abcdef" for c in h_lower):
        length = len(h_lower)
        
        if length == 16:
            return "MySQL323"  # or LM, but MySQL323 more common
        elif length == 32:
            # Could be MD5 or NTLM - context matters
            # If it looks like a typical password hash, assume MD5
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 56:
            return "SHA224"
        elif length == 64:
            return "SHA256"
        elif length == 96:
            return "SHA384"
        elif length == 128:
            return "SHA512"
    
    # SAM format (LM:NTLM)
    if ":" in h and len(h) == 65:
        parts = h.split(":")
        if len(parts) == 2 and len(parts[0]) == 32 and len(parts[1]) == 32:
            if all(c in "0123456789abcdefABCDEF" for c in parts[0] + parts[1]):
                return "SAM"
    
    # Joomla format (hash:salt)
    if ":" in h and len(h) > 32:
        parts = h.split(":")
        if len(parts) == 2 and len(parts[0]) == 32:
            if all(c in "0123456789abcdef" for c in parts[0].lower()):
                return "Joomla"
    
    # Base64-like patterns (but be careful not to catch passwords)
    if len(h) > 20 and h.replace("+", "").replace("/", "").replace("=", "").isalnum():
        # Could be base64 encoded hash, but need more context
        if len(h) % 4 == 0 and h.endswith("="):
            return "Base64"
    
    # Strong plaintext password detection
    h_lower = h.lower()
    
    # Common password patterns (very likely plaintext)
    common_password_patterns = [
        "password", "admin", "user", "test", "guest", "root", "login",
        "pass", "secret", "key", "code", "word", "name", "mail", "123",
        "qwerty", "letmein", "welcome", "monkey", "dragon", "master"
    ]
    
    if any(pattern in h_lower for pattern in common_password_patterns):
        return ""
    
    # If it's short (< 16 chars) and has mixed case/numbers/symbols, likely password
    if len(h) < 16:
        has_upper = any(c.isupper() for c in h)
        has_lower = any(c.islower() for c in h) 
        has_digit = any(c.isdigit() for c in h)
        has_symbol = any(not c.isalnum() for c in h)
        
        # If it has 2+ character types and is short, probably password
        char_types = sum([has_upper, has_lower, has_digit, has_symbol])
        if char_types >= 2:
            return ""
    
    # If we get here and it's all alphanumeric with good length, might be hash
    if len(h) >= 16 and h.isalnum() and not h.isdigit():
        # But double-check for password patterns
        if any(c.isupper() for c in h) and any(c.islower() for c in h) and any(c.isdigit() for c in h):
            # Mixed case + numbers in short string = likely password
            if len(h) < 32:
                return ""
    
    # Unknown format
    return ""


def estimate_hash_strength(hash_type: str) -> str:
    """Estimate cracking difficulty based on hash type"""
    if not hash_type:
        return "n/a"
    
    weak_hashes = ["MD5", "SHA1", "MySQL323", "LM", "NTLM"]
    medium_hashes = ["SHA224", "SHA256", "MD5crypt", "MySQL5"]
    strong_hashes = ["bcrypt", "SHA512crypt", "SHA256crypt", "SHA384", "SHA512"]
    
    hash_type_upper = hash_type.upper()
    
    if any(weak in hash_type_upper for weak in weak_hashes):
        return "high"  # High crackability (weak security)
    elif any(medium in hash_type_upper for medium in medium_hashes):
        return "medium"
    elif any(strong in hash_type_upper for strong in strong_hashes):
        return "low"  # Low crackability (strong security)
    else:
        return "unknown"


def get_hashcat_mode(hash_type: str) -> int:
    """Get hashcat mode number for hash type"""
    modes = {
        "MD5": 0,
        "SHA1": 100,
        "SHA224": 1300,
        "SHA256": 1400,
        "SHA384": 10800,
        "SHA512": 1700,
        "NTLM": 1000,
        "LM": 3000,
        "bcrypt": 3200,
        "MD5crypt": 500,
        "SHA256crypt": 7400,
        "SHA512crypt": 1800,
        "MySQL323": 200,
        "MySQL5": 300,
        "WordPress": 400,
        "phpBB3": 400,
        "Joomla": 11,
    }
    
    return modes.get(hash_type, 0)


def get_john_format(hash_type: str) -> str:
    """Get John the Ripper format for hash type"""
    formats = {
        "MD5": "Raw-MD5",
        "SHA1": "Raw-SHA1",
        "SHA256": "Raw-SHA256",
        "SHA512": "Raw-SHA512",
        "NTLM": "NT",
        "LM": "LM",
        "bcrypt": "bcrypt",
        "MD5crypt": "md5crypt",
        "SHA256crypt": "sha256crypt", 
        "SHA512crypt": "sha512crypt",
        "MySQL323": "mysql",
        "MySQL5": "mysql-sha1",
        "WordPress": "phpass",
        "phpBB3": "phpass",
    }
    
    return formats.get(hash_type, "")
