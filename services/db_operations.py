import csv
import os
import time
from datetime import datetime
from config import Config

def _read_csv(file_path):
    """Read a CSV file and return a list of dictionaries."""
    if not os.path.exists(file_path):
        return []
    
    # Try reading the file with retries in case of temporary locks
    for _ in range(5):
        try:
            with open(file_path, mode='r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                return list(reader)
        except IOError:
            time.sleep(0.05)
    return []

def _write_csv(file_path, fieldnames, data):
    """Write list of dictionaries to a CSV file."""
    for _ in range(5):
        try:
            with open(file_path, mode='w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            return True
        except IOError:
            time.sleep(0.05)
    return False

def _append_csv(file_path, fieldnames, row_dict):
    """Append a dictionary row to a CSV file."""
    for _ in range(5):
        try:
            file_exists = os.path.exists(file_path) and os.path.getsize(file_path) > 0
            with open(file_path, mode='a', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row_dict)
            return True
        except IOError:
            time.sleep(0.05)
    return False

# --- User Management ---
USERS_FILE = Config.DB_FOLDER / 'users.csv'
USER_FIELDS = ['username', 'email', 'password_hash', 'full_name', 'mobile_number', 'location', 'created_at', 'bio', 'role', 'organization', 'profile_photo_url', 'provider', 'account_created_date']

def add_user(username, email, password_hash, full_name=None, mobile_number=None, location=None, role=None, organization=None, profile_photo_url=None, provider=None, account_created_date=None):
    """Registers a new user in users.csv."""
    users = _read_csv(USERS_FILE)
    for user in users:
        if user['username'].lower() == username.lower() or user['email'].lower() == email.lower():
            return False, "Username or email already exists."
    
    new_user = {
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'full_name': full_name or username.title(),
        'mobile_number': mobile_number or "",
        'location': location or "Hyderabad, Telangana, India",
        'created_at': datetime.now().isoformat(),
        'bio': '',
        'role': role or 'Threat Analyst',
        'organization': organization or 'Malicious IP Intelligence System',
        'profile_photo_url': profile_photo_url or '',
        'provider': provider or 'local',
        'account_created_date': account_created_date or datetime.now().isoformat()
    }
    success = _append_csv(USERS_FILE, USER_FIELDS, new_user)
    if success:
        return True, "User registered successfully."
    return False, "Database error. Please try again."

def get_user(username):
    """Retrieve user details by username."""
    users = _read_csv(USERS_FILE)
    for user in users:
        if user['username'].lower() == username.lower():
            return user
    return None

def get_user_by_email(email):
    """Retrieve user details by email."""
    users = _read_csv(USERS_FILE)
    for user in users:
        if 'email' in user and user['email'].lower() == email.lower():
            return user
    return None

def update_user(current_username, full_name=None, username=None, email=None, location=None, bio=None, role=None, organization=None):
    """Update a user record and cascade username changes through related records."""
    users = _read_csv(USERS_FILE)
    current_user = None
    for user in users:
        if user['username'].lower() == current_username.lower():
            current_user = user
            break

    if not current_user:
        return False, "User not found."

    target_username = username.strip() if username else current_user['username']
    if target_username.lower() != current_username.lower():
        for user in users:
            if user['username'].lower() == target_username.lower():
                return False, "Username is already taken."

    for user in users:
        if user['username'].lower() == current_username.lower():
            user['username'] = target_username
            user['full_name'] = full_name.strip() if full_name is not None else user.get('full_name', '')
            user['email'] = email.strip() if email is not None else user.get('email', '')
            user['location'] = location.strip() if location is not None else user.get('location', 'Hyderabad, Telangana, India')
            user['bio'] = bio if bio is not None else user.get('bio', '')
            user['role'] = role.strip() if role is not None else user.get('role', 'Threat Analyst')
            user['organization'] = organization.strip() if organization is not None else user.get('organization', 'Malicious IP Intelligence System')
            if 'mobile_number' not in user:
                user['mobile_number'] = ''
            if 'role' not in user or not user['role']:
                user['role'] = 'Threat Analyst'
            if 'organization' not in user or not user['organization']:
                user['organization'] = 'Malicious IP Intelligence System'
            if 'created_at' not in user or not user['created_at']:
                user['created_at'] = datetime.now().isoformat()
            break

    if not _write_csv(USERS_FILE, USER_FIELDS, users):
        return False, "Failed to update user profile."

    if target_username.lower() != current_username.lower():
        history = _read_csv(HISTORY_FILE)
        for row in history:
            if row.get('username', '').lower() == current_username.lower():
                row['username'] = target_username
        _write_csv(HISTORY_FILE, HISTORY_FIELDS, history)

        watchlist = _read_csv(WATCHLIST_FILE)
        for row in watchlist:
            if row.get('username', '').lower() == current_username.lower():
                row['username'] = target_username
        _write_csv(WATCHLIST_FILE, WATCHLIST_FIELDS, watchlist)

    return True, "Profile updated successfully."

# --- Investigation History ---
HISTORY_FILE = Config.DB_FOLDER / 'investigation_history.csv'
HISTORY_FIELDS = [
    'id', 'username', 'ip', 'country', 'isp', 'asn', 'risk_score',
    'classification', 'threat_summary', 'recommendations', 'abuse_score',
    'vt_detections', 'date', 'source'
]

def add_history(username, ip, country, isp, asn, risk_score, classification, threat_summary, recommendations, abuse_score, vt_detections, source='manual'):
    """Log an investigation search to database."""
    history = _read_csv(HISTORY_FILE)
    next_id = str(len(history) + 1)
    
    new_log = {
        'id': next_id,
        'username': username,
        'ip': ip,
        'country': country or 'Unknown',
        'isp': isp or 'Unknown',
        'asn': asn or 'Unknown',
        'risk_score': str(risk_score),
        'classification': classification,
        'threat_summary': threat_summary,
        'recommendations': recommendations,
        'abuse_score': str(abuse_score),
        'vt_detections': str(vt_detections),
        'date': datetime.now().isoformat(),
        'source': source
    }
    _append_csv(HISTORY_FILE, HISTORY_FIELDS, new_log)
    return new_log

def get_history(username=None):
    """Retrieve full history, optionally filtered by user."""
    history = _read_csv(HISTORY_FILE)
    if username:
        return [row for row in history if row['username'].lower() == username.lower()]
    return history

# --- Watchlist ---
WATCHLIST_FILE = Config.DB_FOLDER / 'watchlist.csv'
WATCHLIST_FIELDS = ['ip', 'username', 'risk_score', 'classification', 'date_added', 'reason', 'status']

def add_to_watchlist(ip, username, risk_score, classification, reason, status='Active'):
    """Add a target IP to watchlist."""
    watchlist = _read_csv(WATCHLIST_FILE)
    # Check if already in watchlist for this user
    for row in watchlist:
        if row['ip'] == ip and row['username'].lower() == username.lower():
            return False, "IP is already on your watchlist."
            
    new_entry = {
        'ip': ip,
        'username': username,
        'risk_score': str(risk_score),
        'classification': classification,
        'date_added': datetime.now().isoformat(),
        'reason': reason or 'Security Analyst Review',
        'status': status
    }
    success = _append_csv(WATCHLIST_FILE, WATCHLIST_FIELDS, new_entry)
    if success:
        return True, "IP added to watchlist."
    return False, "Failed to update watchlist."

def remove_from_watchlist(ip, username):
    """Delete an IP from watchlist for a user."""
    watchlist = _read_csv(WATCHLIST_FILE)
    new_watchlist = [row for row in watchlist if not (row['ip'] == ip and row['username'].lower() == username.lower())]
    if len(watchlist) == len(new_watchlist):
        return False, "IP not found in watchlist."
    
    success = _write_csv(WATCHLIST_FILE, WATCHLIST_FIELDS, new_watchlist)
    if success:
        return True, "IP removed from watchlist."
    return False, "Failed to update database."

def get_watchlist(username=None):
    """Retrieve watchlist rows."""
    watchlist = _read_csv(WATCHLIST_FILE)
    if username:
        return [row for row in watchlist if row['username'].lower() == username.lower()]
    return watchlist

def is_in_watchlist(ip, username):
    """Check if IP is active in user's watchlist."""
    watchlist = _read_csv(WATCHLIST_FILE)
    return any(row['ip'] == ip and row['username'].lower() == username.lower() for row in watchlist)

# --- Malicious IPs Cache ---
MALICIOUS_FILE = Config.DB_FOLDER / 'malicious_ips.csv'
MALICIOUS_FIELDS = ['ip', 'risk_score', 'classification', 'last_detected', 'reason']

def add_malicious_ip(ip, risk_score, classification, reason):
    """Update general list of detected malicious IPs."""
    malicious = _read_csv(MALICIOUS_FILE)
    # Check if already present and update, or append
    found = False
    for row in malicious:
        if row['ip'] == ip:
            row['risk_score'] = str(risk_score)
            row['classification'] = classification
            row['last_detected'] = datetime.now().isoformat()
            row['reason'] = reason
            found = True
            break
            
    if found:
        _write_csv(MALICIOUS_FILE, MALICIOUS_FIELDS, malicious)
    else:
        new_row = {
            'ip': ip,
            'risk_score': str(risk_score),
            'classification': classification,
            'last_detected': datetime.now().isoformat(),
            'reason': reason
        }
        _append_csv(MALICIOUS_FILE, MALICIOUS_FIELDS, new_row)
    return True

def get_malicious_ips():
    """Retrieve the general cache of malicious IPs."""
    return _read_csv(MALICIOUS_FILE)

def _migrate_users_schema():
    """Auto-migrate users.csv schema if columns are missing."""
    if not os.path.exists(USERS_FILE):
        return
        
    try:
        users = _read_csv(USERS_FILE)
        if not users:
            return
            
        needs_migration = False
        sample_columns = users[0].keys()
        checked_cols = ['full_name', 'mobile_number', 'location', 'created_at', 'profile_photo_url', 'provider', 'account_created_date']
        for col in checked_cols:
            if col not in sample_columns:
                needs_migration = True
                break
            
        if needs_migration:
            print("[*] Migrating database: upgrading users.csv schema...")
            for user in users:
                if 'full_name' not in user or not user.get('full_name'):
                    user['full_name'] = user.get('username', '').title() or 'Security Analyst'
                if 'mobile_number' not in user:
                    user['mobile_number'] = ""
                if 'location' not in user or not user.get('location'):
                    user['location'] = "Hyderabad, Telangana, India"
                if 'created_at' not in user or not user.get('created_at'):
                    user['created_at'] = datetime.now().isoformat()
                if 'profile_photo_url' not in user:
                    user['profile_photo_url'] = ""
                if 'provider' not in user or not user.get('provider'):
                    user['provider'] = "local"
                if 'account_created_date' not in user or not user.get('account_created_date'):
                    user['account_created_date'] = user.get('created_at') or datetime.now().isoformat()
            
            # Rewrite database file with new columns
            _write_csv(USERS_FILE, USER_FIELDS, users)
            print("[+] Database migration completed successfully.")
    except Exception as e:
        print(f"[-] Database migration error: {e}")

# Run schema migrations automatically on import
_migrate_users_schema()
