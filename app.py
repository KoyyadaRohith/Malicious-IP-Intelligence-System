import os
import hashlib
import ipaddress
import platform
import re
import secrets
import requests
from datetime import datetime, timedelta
from urllib.parse import urlencode
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, send_file

# Load configuration and services
from config import Config
import services.db_operations as db
import services.abuseipdb as abuse
import services.virustotal as vt
import services.whois_lookup as whois
import services.risk_scoring as risk
import services.threat_summary as summary
import services.recommendations as recs
import services.report_generator as report_gen
import services.threat_intel_cache as intel_cache


# Initialize directories
Config.init_folders()

app = Flask(__name__)
app.config.from_object(Config)
app.jinja_env.globals['Config'] = Config

# Password hashing helpers
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Authentication check decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Authorization required. Please log in.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Notification helper — stores activity events in session
def add_notification(icon, color, title, message):
    if 'notifications' not in session:
        session['notifications'] = []
    notifs = session['notifications']
    notifs.insert(0, {
        'icon': icon,
        'color': color,
        'title': title,
        'message': message,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    # Keep only latest 20
    session['notifications'] = notifs[:20]

# Context processor to inject standard global variables
@app.context_processor
def inject_globals():
    avatar_url = None
    if session.get('photo_url'):
        avatar_url = session['photo_url']
    elif 'username' in session:
        avatar_filename = f"{session['username']}.png"
        avatar_filepath = os.path.join(app.static_folder, 'uploads', 'avatars', avatar_filename)
        if os.path.exists(avatar_filepath):
            avatar_url = url_for('static', filename=f'uploads/avatars/{avatar_filename}')
            
    return {
        'time_now': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'active_page': request.endpoint,
        'global_avatar_url': avatar_url,
        'notifications': session.get('notifications', [])
    }

# Helper: Load mock settings state for current user
def get_user_settings():
    if 'settings' not in session:
        session['settings'] = {}
        
    cfg = session['settings']
    # If keys are defined in Config but not in session, auto-inject them
    if Config.ABUSEIPDB_API_KEY.strip() and not cfg.get('abuseipdb_key'):
        cfg['abuseipdb_key'] = Config.ABUSEIPDB_API_KEY
        cfg['mock_mode'] = False
    if Config.VIRUSTOTAL_API_KEY.strip() and not cfg.get('virustotal_key'):
        cfg['virustotal_key'] = Config.VIRUSTOTAL_API_KEY
        cfg['mock_mode'] = False
        
    # Standard fallbacks
    if 'auto_watchlist_score' not in cfg:
        cfg['auto_watchlist_score'] = 75
    if 'mock_mode' not in cfg:
        has_keys = bool(Config.ABUSEIPDB_API_KEY.strip()) or bool(Config.VIRUSTOTAL_API_KEY.strip())
        cfg['mock_mode'] = not has_keys
        
    session['settings'] = cfg
    return session['settings']

# --- PUBLIC ROUTES ---

@app.route('/')
@app.route('/home')
def home():
    # Read database states to compile home page analytics
    history = db.get_history()
    watchlist = db.get_watchlist()
    
    total_scans = len(history)
    malicious_scans = len([r for r in history if r['classification'] == 'Malicious'])
    watchlist_count = len(watchlist)
    
    # Reports count: unique batch runs + manual scans
    total_reports = total_scans
    
    return render_template(
        'home.html',
        total_scans=total_scans,
        malicious_scans=malicious_scans,
        watchlist_count=watchlist_count,
        total_reports=total_reports
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        flashes = session.pop('_flashes', None)
        session.clear()
        if flashes:
            session['_flashes'] = flashes
        
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = db.get_user(username)
        if user and user['password_hash'] == hash_password(password):
            session['username'] = user['username']
            session['email'] = user['email']
            session['full_name'] = user.get('full_name', user['username'].title())
            session['mobile_number'] = user.get('mobile_number', '')
            add_notification('log-in', 'var(--color-safe)', 'Login Successful', f"Welcome back, Analyst {session['full_name']}.")
            flash(f"Welcome back, Analyst {session['full_name']}.", "success")
            return redirect(url_for('dashboard'))
            
        flash("Invalid credentials. Please try again.", "error")
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        session.clear()
        
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        mobile_number = request.form.get('mobile_number', '').strip()
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        if not full_name:
            flash("Full name is required.", "error")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('register.html')
            
        if len(username) < 3 or len(password) < 6:
            flash("Username min 3 characters, Password min 6 characters.", "error")
            return render_template('register.html')
            
        hashed = hash_password(password)
        success, message = db.add_user(username, email, hashed, full_name=full_name, mobile_number=mobile_number)
        if success:
            flash("Access credentials generated successfully. Please sign in.", "success")
            return redirect(url_for('login'))
        else:
            flash(message, "error")
            
    return render_template('register.html')





@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        flash(f"Security key reset token dispatched to {email}. Check your corporate inbox.", "success")
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/clear-notifications', methods=['POST'])
@login_required
def clear_notifications():
    session['notifications'] = []
    return jsonify(success=True)

# --- GOOGLE OAUTH ROUTES ---

@app.route('/login/google')
def login_google():
    """Initiates Google OAuth 2.0 flow or falls back to mock flow if credentials are not configured."""
    client_id = app.config.get('GOOGLE_CLIENT_ID', '').strip()
    client_secret = app.config.get('GOOGLE_CLIENT_SECRET', '').strip()
    
    # If keys are missing, execute the mock flow
    if not client_id or not client_secret:
        return redirect(url_for('login_google_mock_consent'))
        
    # Otherwise, execute real Google OAuth flow
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': url_for('google_callback', _external=True),
        'scope': 'openid email profile',
        'state': state,
        'prompt': 'select_account'
    }
    return redirect(f"{google_auth_url}?{urlencode(params)}")

@app.route('/login/google/mock-consent', methods=['GET', 'POST'])
def login_google_mock_consent():
    """Mock Google Consent page for local development."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        picture = request.form.get('picture', '').strip()
        
        if not email or not name:
            flash("Mock login details are incomplete.", "error")
            return redirect(url_for('login'))
            
        # Store mock account info temporarily in session
        session['mock_oauth_user'] = {
            'email': email,
            'name': name,
            'picture': picture or f"https://lh3.googleusercontent.com/a/default-user"
        }
        
        # Redirect to callback with a dummy code
        return redirect(url_for('google_callback', code='mock_auth_code_12345'))
        
    return render_template('google_mock_consent.html')

@app.route('/login/google/callback', methods=['GET', 'POST'])
def google_callback():
    """OAuth 2.0 callback endpoint: verifies profile info (via JWT/tokeninfo or mock) and registers/logs in the user."""
    client_id = app.config.get('GOOGLE_CLIENT_ID', '').strip()
    client_secret = app.config.get('GOOGLE_CLIENT_SECRET', '').strip()
    
    # Detect if we are in mock mode
    is_mock = not client_id or not client_secret
    
    user_info = None
    
    # 1. Handle real Google Identity Services (GSI) POST request with JWT credential
    if request.method == 'POST' and 'credential' in request.form:
        if is_mock:
            flash("System configured in mock authentication mode. GSI POST payload rejected.", "error")
            return redirect(url_for('login'))
            
        credential = request.form['credential']
        tokeninfo_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={credential}"
        
        try:
            response = requests.get(tokeninfo_url, timeout=10)
            if response.status_code != 200:
                flash("Authentication failed: Google ID token verification rejected.", "error")
                return redirect(url_for('login'))
                
            user_info = response.json()
            # Safety check: Verify the ID token was issued to our Client ID
            if user_info.get('aud') != client_id:
                flash("OAuth verification error: Client audience mismatch.", "error")
                return redirect(url_for('login'))
        except requests.RequestException as e:
            flash(f"Connection error to Google verification endpoint: {str(e)}", "error")
            return redirect(url_for('login'))
            
    # 2. Handle mock login redirection
    elif is_mock:
        # Retrieve mock account details
        user_info = session.pop('mock_oauth_user', None)
        if not user_info:
            # Check if testing client POSTed direct mock info
            if request.method == 'POST':
                user_info = {
                    'email': request.form.get('email'),
                    'name': request.form.get('name'),
                    'picture': request.form.get('picture')
                }
            if not user_info or not user_info.get('email'):
                flash("Mock authentication session timed out or was invalid.", "error")
                return redirect(url_for('login'))
                
    # 3. Handle legacy real Google redirect/code flow (GET)
    else:
        # Verify OAuth state
        returned_state = request.args.get('state')
        saved_state = session.pop('oauth_state', None)
        if not returned_state or returned_state != saved_state:
            flash("OAuth state verification failed. Potential cross-site request forgery detected.", "error")
            return redirect(url_for('login'))
            
        # Exchange code for access token
        code = request.args.get('code')
        if not code:
            flash("Authorization code not returned by Google.", "error")
            return redirect(url_for('login'))
            
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'code': code,
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': url_for('google_callback', _external=True),
            'grant_type': 'authorization_code'
        }
        
        try:
            response = requests.post(token_url, data=data, timeout=10)
            response.raise_for_status()
            token_json = response.json()
            access_token = token_json.get('access_token')
            
            if not access_token:
                flash("Access token exchange failed.", "error")
                return redirect(url_for('login'))
                
            # Fetch user info
            userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"
            headers = {'Authorization': f'Bearer {access_token}'}
            userinfo_response = requests.get(userinfo_url, headers=headers, timeout=10)
            userinfo_response.raise_for_status()
            user_info = userinfo_response.json()
        except requests.RequestException as e:
            flash(f"Connection error to Google Authentication server: {str(e)}", "error")
            return redirect(url_for('login'))

    # Extract user identity attributes
    email = user_info.get('email', '').strip()
    full_name = user_info.get('name', '').strip()
    picture = user_info.get('picture', '')
    
    if not email:
        flash("Email address not returned by identity provider.", "error")
        return redirect(url_for('login'))

    # Check if email is registered
    user = db.get_user_by_email(email)
    
    if user:
        # Log existing user in
        session['username'] = user['username']
        session['email'] = user['email']
        session['full_name'] = user.get('full_name', user['username'].title())
        session['mobile_number'] = user.get('mobile_number', '')
        if picture or user.get('profile_photo_url'):
            session['photo_url'] = user.get('profile_photo_url') or picture
            
        flash(f"Signed in via Google. Welcome back, Analyst {session['full_name']}.", "success")
        return redirect(url_for('dashboard'))
    else:
        # Register user dynamically (Google Sign-Up Flow)
        # Generate unique sanitized username from email prefix
        base_username = email.split('@')[0].replace('.', '_').replace('-', '_')
        username = base_username
        counter = 1
        while db.get_user(username) is not None:
            username = f"{base_username}_{counter}"
            counter += 1
            
        # Google users do not use passwords. Generate a random password hash
        password_hash = hash_password(secrets.token_hex(24))
        
        success, message = db.add_user(
            username=username,
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            profile_photo_url=picture,
            provider='google'
        )
        
        if success:
            session['username'] = username
            session['email'] = email
            session['full_name'] = full_name
            session['mobile_number'] = ''
            if picture:
                session['photo_url'] = picture
                
            flash(f"Account generated via Google. Welcome, Analyst {full_name}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash(f"Sign-up registration failed: {message}", "error")
            return redirect(url_for('login'))

# --- AUTHENTICATED PLATFORM PAGES ---

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    history = db.get_history(username)
    watchlist = db.get_watchlist(username)
    
    # Calculate widget states
    stats = {
        'total_scans': len(history),
        'safe_scans': len([r for r in history if r['classification'] == 'Safe']),
        'suspicious_scans': len([r for r in history if r['classification'] == 'Suspicious']),
        'malicious_scans': len([r for r in history if r['classification'] == 'Malicious']),
        'watchlist_count': len(watchlist),
        'total_reports': len(history) # every scan has export capability
    }
    
    # Compile 7-day trend history
    labels = []
    counts = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append((datetime.now() - timedelta(days=i)).strftime('%b %d'))
        day_scans = len([r for r in history if r['date'].startswith(day)])
        counts.append(day_scans)
        
    trend_labels = labels
    trend_counts = counts
    
    # Filter last 10 activities for grid
    recent_activity = sorted(history, key=lambda x: x['date'], reverse=True)[:10]
    
    return render_template(
        'dashboard.html',
        stats=stats,
        trend_labels=trend_labels,
        trend_counts=trend_counts,
        recent_activity=recent_activity
    )

@app.route('/analytics')
@login_required
def threat_analytics():
    username = session['username']
    history = db.get_history(username)
    watchlist = db.get_watchlist(username)

    total_scans = len(history)
    threat_breakdown = {
        'Safe': len([r for r in history if r['classification'] == 'Safe']),
        'Suspicious': len([r for r in history if r['classification'] == 'Suspicious']),
        'Malicious': len([r for r in history if r['classification'] == 'Malicious'])
    }
    total_watchlist = len(watchlist)
    total_reports = total_scans

    labels = []
    counts = []
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        labels.append((datetime.now() - timedelta(days=i)).strftime('%b %d'))
        counts.append(len([r for r in history if r['date'].startswith(day)]))

    recent_scans = sorted(history, key=lambda x: x['date'], reverse=True)[:8]
    all_scans = sorted(history, key=lambda x: x['date'], reverse=True)

    return render_template(
        'threat_analytics.html',
        total_scans=total_scans,
        threat_breakdown=threat_breakdown,
        total_watchlist=total_watchlist,
        total_reports=total_reports,
        trend_labels=labels,
        trend_counts=counts,
        recent_scans=recent_scans,
        all_scans=all_scans
    )

@app.route('/investigate', methods=['GET', 'POST'])
@login_required
def ip_investigation():
    details = None
    ip_address = request.args.get('ip_address', '').strip()
    error = None
    is_watched = False


    # If POST query or query parameter exists
    if request.method == 'POST':
        ip_address = request.form.get('ip_address', '').strip()

    # Optional: when explicitly requested, reuse last computed details for this IP
    # to prevent classification from changing after an action like Watchlist.
    use_cached = request.args.get('use_cached', '').strip() == '1'

    # If we have an IP, validate or reuse cached details
    if ip_address:
        try:
            ipaddress.ip_address(ip_address)

            # Reuse cached investigation details when requested
            if use_cached:
                cached_map = session.get('last_investigation_details', {})
                cached = cached_map.get(ip_address)
                if cached:
                    details = cached

            # If no cached details were used/found, compute via persistent cache-first pipeline
            if details is None:
                cfg = get_user_settings()

                # If user asked to bypass session cache, still obey 24h persistent cache.
                # A manual refresh action will pass force_refresh=1.
                force_refresh = request.args.get('refresh', '').strip() == '1' or request.form.get('refresh', '').strip() == '1'

                try:
                    details = intel_cache.get_cached_intel(
                        ip_address,
                        cfg,
                        ttl_hours=24,
                        force_refresh=force_refresh
                    )
                except ValueError:
                    error = f"'{ip_address}' is not a valid IPv4 network address format."
                    details = None
                    
                    # Ensure watchlist state isn't stale
                    is_watched = False
                    
                    return render_template(
                        'ip_investigation.html',
                        ip_address=ip_address,
                        details=None,
                        error=error,
                        is_watched=is_watched
                    )


                # Persist computed details in session so subsequent actions (Watchlist)
                # can render the same classification.
                if 'last_investigation_details' not in session:
                    session['last_investigation_details'] = {}
                session['last_investigation_details'][ip_address] = details

                # Persist history/logs and malicious cache only when we actually computed
                # (cache hits also represent a computed record for the UI).
                cfg = get_user_settings()
                risk_profile = details.get('risk', {})
                abuse_data = details.get('abuse', {})
                vt_data = details.get('vt', {})
                whois_data = details.get('whois', {})
                threat_sum = details.get('summary', '')
                recs_list = details.get('recommendations', [])


                # Log results to History
                # NOTE: We preserve existing behavior (history append) for both cache hits and refreshes.
                db.add_history(
                    username=session['username'],
                    ip=ip_address,
                    country=whois_data.get('country'),
                    isp=whois_data.get('isp'),
                    asn=whois_data.get('asn'),
                    risk_score=risk_profile.get('score', 0),
                    classification=risk_profile.get('classification', 'Safe'),
                    threat_summary=threat_sum,
                    recommendations="; ".join([r['action'] for r in recs_list]) if recs_list else '',
                    abuse_score=abuse_data.get('abuse_score', 0),
                    vt_detections=vt_data.get('malicious_count', 0),
                    source='manual'
                )

                # Cache known malicious targets
                if risk_profile.get('classification') == 'Malicious':
                    db.add_malicious_ip(ip_address, risk_profile.get('score', 0), 'Malicious', threat_sum)


                # Add notification for the search
                intel_meta = details.get('intel_meta', {})
                cache_age = intel_meta.get('cache_age_hours', '')
                source_status = intel_meta.get('source_status', 'Refreshed Result' if request.args.get('refresh','').strip()=='1' else 'Computed Result')

                add_notification(
                    'search',
                    'var(--color-safe)' if risk_profile.get('classification') == 'Safe' else 'var(--color-suspicious)' if risk_profile.get('classification') == 'Suspicious' else 'var(--color-malicious)',
                    f"IP Investigated: {ip_address}",
                    f"Classification: {risk_profile.get('classification')} — Risk Score: {risk_profile.get('score')}/100 | {source_status} | Cache Age: {cache_age}h"
                )


                # Automation check: check if it matches auto-watchlist threshold
                auto_watchlist_score = int(cfg.get('auto_watchlist_score', 75))
                if risk_profile.get('score', 0) >= auto_watchlist_score:

                    db.add_to_watchlist(
                        ip_address, session['username'], risk_profile['score'],
                        risk_profile['classification'], "Auto-Watchlist: Score limit exceeded"
                    )

            # Check watchlist state (always reflect latest DB state)
            is_watched = db.is_in_watchlist(ip_address, session['username'])

        except ValueError:
            error = f"'{ip_address}' is not a valid IPv4 network address format."

    # Provide cache transparency metadata to UI even on cache hits.
    intel_meta = None
    if details:
        intel_meta = details.get('intel_meta')

    return render_template(
        'ip_investigation.html',
        ip_address=ip_address,
        details=details,
        error=error,
        is_watched=is_watched,
        intel_meta=intel_meta
    )


@app.route('/results/details/<ip_address>')
@login_required
def investigation_results(ip_address):
    # Route helper to redirect grid clicks straight into search diagnostics
    return redirect(url_for('ip_investigation', ip_address=ip_address))

@app.route('/file-upload', methods=['GET', 'POST'])
@login_required
def file_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file object selected.", "error")
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash("Filename cannot be blank.", "error")
            return redirect(request.url)
            
        if file:
            filename = file.filename
            ext = os.path.splitext(filename)[1].lower()
            
            if ext not in ['.csv', '.txt', '.log']:
                flash("File format not supported. Upload .csv, .txt, or log dumps.", "error")
                return redirect(request.url)
                
            # Read files data
            content = file.read().decode('utf-8', errors='ignore')
            
            # Extract IPs
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, content)
            unique_ips = list(set(ips))
            
            if not unique_ips:
                flash("No valid IP address targets identified in file structure.", "error")
                return redirect(request.url)
                
            # Cache target IPs in session for interactive load page
            session['parsed_ips'] = unique_ips
            session['upload_filename'] = filename
            add_notification('upload-cloud', 'var(--primary)', f'File Uploaded: {filename}', f'{len(unique_ips)} unique IPv4 targets extracted for analysis.')
            
            return redirect(url_for('analysis_pipeline'))
            
    return render_template('file_upload.html')

@app.route('/analysis')
@login_required
def analysis_pipeline():
    unique_ips = session.get('parsed_ips', [])
    filename = session.get('upload_filename', 'Unknown')
    return render_template('analysis.html', unique_ips=unique_ips, filename=filename)

@app.route('/api/analyze-single')
@login_required
def api_analyze_single():
    ip = request.args.get('ip', '').strip()
    refresh = request.args.get('refresh', '').strip() == '1'

    if not ip:

        return jsonify({'error': 'Missing target'}), 400
        
    # cache-first: prevents inconsistent results + reduces API calls
    cfg = get_user_settings()
    try:
        details = intel_cache.get_cached_intel(ip, cfg, ttl_hours=24, force_refresh=refresh)

    except ValueError:
        return jsonify({'error': 'Invalid IP format'}), 400

    risk_profile = details.get('risk', {})
    abuse_data = details.get('abuse', {})
    vt_data = details.get('vt', {})
    whois_data = details.get('whois', {})
    threat_sum = details.get('summary', '')
    recs_list = details.get('recommendations', [])

    
    # Save automatically to operational history archive (marked as bulk parsed)
    db.add_history(
        username=session['username'],
        ip=ip,
        country=whois_data.get('country'),
        isp=whois_data.get('isp'),
        asn=whois_data.get('asn'),
        risk_score=risk_profile.get('score', 0),
        classification=risk_profile.get('classification', 'Safe'),
        threat_summary=threat_sum,
        recommendations="; ".join([r['action'] for r in recs_list]) if recs_list else '',
        abuse_score=abuse_data.get('abuse_score', 0),
        vt_detections=vt_data.get('malicious_count', 0),
        source=session.get('upload_filename', 'bulk_upload')
    )

    
    if risk_profile.get('classification') == 'Malicious':
        db.add_malicious_ip(ip, risk_profile.get('score', 0), 'Malicious', threat_sum)

        
    # Auto Watchlist Threshold check
    auto_watchlist_score = int(cfg.get('auto_watchlist_score', 75))
    if risk_profile.get('score', 0) >= auto_watchlist_score:

        db.add_to_watchlist(
            ip, session['username'], risk_profile.get('score', 0),
            risk_profile.get('classification', 'Safe'), "Auto-Watchlist Ingest Threshold Exceeded"
        )

        
    intel_meta = details.get('intel_meta', {}) if 'details' in locals() else {}


    return jsonify({
        'ip': ip,
        'risk_score': risk_profile.get('score', 0),
        'classification': risk_profile.get('classification', 'Safe'),
        'country': whois_data.get('country'),
        'isp': whois_data.get('isp'),
        'asn': whois_data.get('asn'),
        'cache_age_hours': intel_meta.get('cache_age_hours', ''),
        'source_status': intel_meta.get('source_status', '')
    })





@app.route('/api/save-bulk-session', methods=['POST'])

@login_required
def save_bulk_session():
    data = request.get_json()
    filename = data.get('filename')
    results = data.get('results', [])
    
    # Unique batch code: filename + timestamp hash
    batch_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    batch_id = f"{filename}_{batch_timestamp}".replace('.', '_').replace(' ', '_')
    
    # We update the source values in history matching these results to index this batch
    history = db.get_history()
    for res in results:
        # Match recent additions from bulk file upload in history and tag them
        for row in reversed(history):
            if row.get('username', '').lower() == session['username'].lower() and row['ip'] == res['ip'] and row['source'] == filename:
                row['source'] = batch_id
                break
                
    # Rewrite the updated history entries back
    db._write_csv(db.HISTORY_FILE, db.HISTORY_FIELDS, history)
    
    # Return batch reference ID
    return jsonify({'batch_id': batch_id})

@app.route('/results')
@login_required
def results_console():
    batch_id = request.args.get('batch_id', '').strip()
    if not batch_id:
        flash("Operational batch ID not found.", "error")
        return redirect(url_for('file_upload'))
        
    # Query history for matches
    history = db.get_history(session['username'])
    results = [row for row in history if row['source'] == batch_id]
    
    if not results:
        flash("No diagnostic logs found matching batch ID.", "error")
        return redirect(url_for('file_upload'))
        
    # Calculate bulk metrics
    stats = {
        'total': len(results),
        'safe': len([r for r in results if r['classification'] == 'Safe']),
        'suspicious': len([r for r in results if r['classification'] == 'Suspicious']),
        'malicious': len([r for r in results if r['classification'] == 'Malicious'])
    }
    
    # Metadata details
    # Extract filename from batch_id (split before timestamp hash)
    parts = batch_id.split('_')
    filename = "_".join(parts[:-2]).replace('_csv', '.csv').replace('_txt', '.txt').replace('_log', '.log')
    
    file_metadata = {
        'filename': filename,
        'batch_id': batch_id
    }
    
    return render_template(
        'results.html',
        results=results,
        stats=stats,
        file_metadata=file_metadata,
        batch_id=batch_id
    )

@app.route('/watchlist')
@login_required
def watchlist():
    watchlist_data = db.get_watchlist(session['username'])
    return render_template('watchlist.html', watchlist=watchlist_data)

@app.route('/watchlist/add', methods=['POST'])
@login_required
def watchlist_add():
    ip = request.form['ip']
    score = request.form['risk_score']
    classification = request.form['classification']
    reason = request.form['reason']
    
    success, message = db.add_to_watchlist(ip, session['username'], score, classification, reason)
    if success:
        add_notification('eye', 'var(--color-suspicious)', f'Watchlist: {ip}', f'{ip} added to watchlist ({classification}).')
        flash(f"{ip} logged to watchlist register.", "success")
    else:
        flash(message, "error")
    # Redirect back to the investigation page while reusing cached details
    # so the displayed classification doesn't change after adding to watchlist.
    return redirect(url_for('ip_investigation', ip_address=ip, use_cached=1))

@app.route('/watchlist/delete', methods=['POST'])
@login_required
def watchlist_delete():
    ip = request.form['ip']
    success = db.remove_from_watchlist(ip, session['username'])
    if success:
        add_notification('eye-off', 'var(--text-muted)', f'Unwatched: {ip}', f'{ip} removed from watchlist surveillance.')
        flash(f"{ip} purged from watchlist surveillance.", "success")
    else:
        flash("Purge failed. IP address not found.", "error")
        
    # Redirect back to caller (watchlist panel or search console)
    referrer = request.referrer
    if referrer and 'watchlist' in referrer:
        return redirect(url_for('watchlist'))
    # Redirect back to the investigation page while reusing cached details
    # so the displayed classification doesn't change after watchlist actions.
    return redirect(url_for('ip_investigation', ip_address=ip, use_cached=1))

@app.route('/history')
@login_required
def history():
    history_data = db.get_history(session['username'])
    # Sort history by date descending
    history_sorted = sorted(history_data, key=lambda x: x['date'], reverse=True)
    return render_template('history.html', history=history_sorted)

@app.route('/reports')
@login_required
def reports():
    history = db.get_history(session['username'])
    
    # Pull unique bulk batch sources
    # Individual lookup sources are marked 'manual'
    unique_batches = list(set([r['source'] for r in history if r['source'] != 'manual']))
    
    report_list = []
    
    # 1. Populate individual reports
    # Every unique search log counts as an individual PDF download
    manual_searches = [r for r in history if r['source'] == 'manual']
    # Limit report cards to last 15 manual lookups to prevent visual clutter
    for row in sorted(manual_searches, key=lambda x: x['date'], reverse=True)[:15]:
        report_list.append({
            'type': 'individual',
            'title': f"Threat Reputation Report: {row['ip']}",
            'date': row['date'].split('T')[0] + " " + row['date'].split('T')[1][:5],
            'scope': f"{row['classification']} ({row['risk_score']}/100)",
            'ip': row['ip']
        })
        
    # 2. Populate bulk report items
    for batch in unique_batches:
        batch_rows = [r for r in history if r['source'] == batch]
        if batch_rows:
            # Extract filename from batch_id
            parts = batch.split('_')
            filename = "_".join(parts[:-2]).replace('_csv', '.csv').replace('_txt', '.txt').replace('_log', '.log')
            
            report_list.append({
                'type': 'bulk',
                'title': f"Bulk Ingestion Audit: {filename}",
                'date': batch_rows[0]['date'].split('T')[0] + " " + batch_rows[0]['date'].split('T')[1][:5],
                'scope': f"{len(batch_rows)} IP targets",
                'batch_id': batch
            })
            
    # Sort reports list by date descending
    report_list_sorted = sorted(report_list, key=lambda x: x['date'], reverse=True)
    
    return render_template('reports.html', reports=report_list_sorted)

@app.route('/reports/download/<report_id>')
@login_required
def download_report(report_id):
    username = session['username']
    history = db.get_history(username)
    
    # Case 1: Download individual report (TXT or PDF style HTML print page)
    if report_id.startswith('individual_'):
        ip = report_id.replace('individual_', '')
        # Find matching details in history
        row = next((r for r in history if r['ip'] == ip and r['source'] == 'manual'), None)
        if not row:
            # Try finding it in any bulk entries as fallback
            row = next((r for r in history if r['ip'] == ip), None)
            
        if not row:
            flash("Target log data not found.", "error")
            return redirect(url_for('reports'))
            
        # Reconstruct details dictionary from the database record row directly to bypass redundant network requests
        risk_profile = {
            'score': int(row.get('risk_score', 0)),
            'classification': row.get('classification', 'Safe')
        }
        
        try:
            abuse_score = int(row.get('abuse_score', 0))
        except (ValueError, TypeError):
            abuse_score = 0
            
        try:
            vt_detections = int(row.get('vt_detections', 0))
        except (ValueError, TypeError):
            vt_detections = 0
            
        abuse_data = {
            'ip': ip,
            'abuse_score': abuse_score,
            'total_reports': abuse_score,
            'last_reported_at': row.get('date'),
            'country_code': '',
            'country_name': row.get('country', 'Unknown'),
            'isp': row.get('isp', 'Unknown ISP'),
            'domain': row.get('isp', 'unknown').lower().split(',')[0].replace(' ', '') + '.com',
            'usage_type': 'Commercial',
            'is_mock': True
        }
        
        vt_data = {
            'ip': ip,
            'malicious_count': vt_detections,
            'suspicious_count': 0,
            'harmless_count': 90 - vt_detections,
            'undetected_count': 0,
            'total_engines': 90,
            'reputation_score': -vt_detections,
            'tags': [],
            'network': f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0/16" if '.' in ip else '',
            'asn': row.get('asn', '0'),
            'is_mock': True
        }
        
        whois_data = {
            'ip': ip,
            'country': row.get('country', 'Unknown'),
            'country_code': '',
            'city': 'Unknown',
            'region': 'Unknown',
            'isp': row.get('isp', 'Unknown'),
            'org': row.get('isp', 'Unknown'),
            'asn': row.get('asn', 'Unknown'),
            'asn_org': row.get('isp', 'Unknown'),
            'created_date': 'Unknown',
            'updated_date': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'timezone': 'UTC',
            'is_mock': True
        }
        
        recs_list = recs.get_recommendations(row.get('classification', 'Safe'))
        
        details = {
            'ip': ip,
            'risk': risk_profile,
            'abuse': abuse_data,
            'vt': vt_data,
            'whois': whois_data,
            'summary': row.get('threat_summary', ''),
            'recommendations': recs_list
        }
        
        # Save individual HTML file to reports/pdf/
        html_content = report_gen.generate_html_print_individual(details)
        filename = f"MaliciousIP_Report_{ip}.html"
        file_path = Config.REPORTS_PDF / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        add_notification('file-down', 'var(--primary)', f'Report Exported: {ip}', f'Individual threat report downloaded for {ip}.')
        
        return send_file(
            file_path,
            mimetype="text/html",
            as_attachment=False,
            download_name=filename
        )
            
    # Case 2: Download bulk report formats
    elif report_id.startswith('bulk_'):
        parts = report_id.split('_')
        format_type = parts[-1]
        
        # Reconstruct batch ID
        if format_type in ['csv', 'txt']:
            batch_id = "_".join(parts[1:-1])
        else:
            batch_id = "_".join(parts[1:])
            format_type = 'pdf' # default print HTML page
            
        # Query matching database rows
        batch_results = [r for r in history if r['source'] == batch_id]
        if not batch_results:
            flash("Ingestion batch records not located.", "error")
            return redirect(url_for('reports'))
            
        # Extract filename
        parts_id = batch_id.split('_')
        filename = "_".join(parts_id[:-2])
        
        stats = {
            'total': len(batch_results),
            'safe': len([r for r in batch_results if r['classification'] == 'Safe']),
            'suspicious': len([r for r in batch_results if r['classification'] == 'Suspicious']),
            'malicious': len([r for r in batch_results if r['classification'] == 'Malicious'])
        }
        metadata = {'filename': filename}
        
        if format_type == 'csv':
            # Export CSV file download
            csv_data = report_gen.generate_csv_report(batch_results, db.HISTORY_FIELDS)
            fn = f"MaliciousIP_Batch_Report_{filename}.csv"
            file_path = Config.REPORTS_CSV / fn
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
                
            return send_file(
                file_path,
                mimetype="text/csv",
                as_attachment=True,
                download_name=fn
            )
            
        elif format_type == 'txt':
            
            # Export TXT summary download
            txt_data = report_gen.generate_txt_bulk(batch_results, metadata, stats)
            fn = f"MaliciousIP_Batch_Report_{filename}.txt"
            file_path = Config.REPORTS_TXT / fn
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
                
            return send_file(
                file_path,
                mimetype="text/plain",
                as_attachment=True,
                download_name=fn
            )
            
        else: # Print HTML window
            html_content = report_gen.generate_html_print_bulk(batch_results, metadata, stats)
            fn = f"MaliciousIP_Batch_Report_{filename}.html"
            file_path = Config.REPORTS_PDF / fn
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
                
            return send_file(
                file_path,
                mimetype="text/html",
                as_attachment=False,
                download_name=fn
            )
            
    # Case 3: History & Watchlist general backups (CSV and TXT)
    elif report_id in ['history_csv', 'watchlist_csv', 'history_txt', 'watchlist_txt']:
        if report_id == 'history_csv':
            csv_data = report_gen.generate_csv_report(history, db.HISTORY_FIELDS)
            fn = "MaliciousIP_Investigation_History_Audit.csv"
            file_path = Config.REPORTS_CSV / fn
            mimetype = "text/csv"
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
        elif report_id == 'history_txt':
            txt_data = report_gen.generate_txt_history(history)
            fn = "MaliciousIP_Investigation_History_Audit.txt"
            file_path = Config.REPORTS_TXT / fn
            mimetype = "text/plain"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
        elif report_id == 'watchlist_csv':
            watchlist_data = db.get_watchlist(username)
            csv_data = report_gen.generate_csv_report(watchlist_data, db.WATCHLIST_FIELDS)
            fn = "MaliciousIP_Watchlist_Audit.csv"
            file_path = Config.REPORTS_CSV / fn
            mimetype = "text/csv"
            with open(file_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
        else: # watchlist_txt
            watchlist_data = db.get_watchlist(username)
            txt_data = report_gen.generate_txt_watchlist(watchlist_data)
            fn = "MaliciousIP_Watchlist_Audit.txt"
            file_path = Config.REPORTS_TXT / fn
            mimetype = "text/plain"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(txt_data)
            
        return send_file(
            file_path,
            mimetype=mimetype,
            as_attachment=True,
            download_name=fn
        )
        
    flash("Report code not recognized.", "error")
    return redirect(url_for('reports'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.get_user(session['username'])
    if not user:
        flash("User profile not found. Please sign in again.", "error")
        return redirect(url_for('logout'))

    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        full_name = data.get('full_name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        location = data.get('location', '').strip()
        role = data.get('role', '').strip()
        organization = data.get('organization', '').strip()
        bio = data.get('bio', '').strip()

        if not full_name or not username or not email:
            return jsonify(success=False, message="Full Name, Username, and Email are required."), 400

        old_username = session['username']
        success, message = db.update_user(
            current_username=old_username,
            full_name=full_name,
            username=username,
            email=email,
            location=location or "Hyderabad, Telangana, India",
            bio=bio,
            role=role or 'Threat Analyst',
            organization=organization or 'Malicious IP Intelligence System'
        )
        if not success:
            return jsonify(success=False, message=message), 400

        if username and username != old_username:
            avatar_dir = os.path.join(app.static_folder, 'uploads', 'avatars')
            old_avatar = os.path.join(avatar_dir, f"{old_username}.png")
            new_avatar = os.path.join(avatar_dir, f"{username}.png")
            try:
                if os.path.exists(old_avatar):
                    os.replace(old_avatar, new_avatar)
            except OSError:
                pass

        session['username'] = username
        session['email'] = email
        session['full_name'] = full_name
        add_notification('user', 'var(--primary)', 'Profile Updated', f'Profile details saved for {full_name}.')

        updated_user = db.get_user(username)
        return jsonify(success=True, message=message, user={
            'full_name': updated_user.get('full_name', ''),
            'username': updated_user.get('username', ''),
            'email': updated_user.get('email', ''),
            'location': updated_user.get('location', ''),
            'role': updated_user.get('role', 'Threat Analyst'),
            'organization': updated_user.get('organization', 'Malicious IP Intelligence System'),
            'created_at': updated_user.get('created_at', ''),
            'bio': updated_user.get('bio', '')
        })

    history = db.get_history(session['username'])
    watchlist = db.get_watchlist(session['username'])
    stats = {
        'total_scans': len(history),
        'watchlist_count': len(watchlist),
        'total_reports': len(history)
    }
    member_since = ''
    if user.get('created_at'):
        try:
            member_since = datetime.fromisoformat(user['created_at']).strftime('%B %d, %Y')
        except ValueError:
            member_since = user['created_at']

    return render_template('profile.html', user=user, stats=stats, member_since=member_since)

@app.route('/profile/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify(success=False, message="No image file provided."), 400
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify(success=False, message="Empty filename."), 400
        
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.gif']:
        return jsonify(success=False, message="Supported formats: PNG, JPG, JPEG, GIF."), 400
        
    # Save file
    avatar_dir = os.path.join(app.static_folder, 'uploads', 'avatars')
    os.makedirs(avatar_dir, exist_ok=True)
    
    filename = f"{session['username']}.png"
    filepath = os.path.join(avatar_dir, filename)
    file.save(filepath)
    
    import time
    avatar_url = url_for('static', filename=f'uploads/avatars/{filename}') + f"?t={int(time.time())}"
    return jsonify(success=True, message="Profile picture updated successfully.", avatar_url=avatar_url)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    cfg = get_user_settings()
    
    if request.method == 'POST':
        # Update settings dict from form inputs
        for key, val in request.form.items():
            if key in ['mock_mode', 'email_alerts', 'desktop_notifications', 'include_whois']:
                continue
            cfg[key] = val.strip()
            
        # Parse integers
        try:
            cfg['auto_watchlist_score'] = int(request.form.get('auto_watchlist_score', 75))
        except ValueError:
            cfg['auto_watchlist_score'] = 75
            
        # Parse boolean toggles
        cfg['mock_mode'] = cfg.get('mock_mode', True)
        cfg['email_alerts'] = 'email_alerts' in request.form
        cfg['desktop_notifications'] = 'desktop_notifications' in request.form
        cfg['include_whois'] = 'include_whois' in request.form
        
        session['settings'] = cfg
        
        # Verify if API keys are provided when mock mode is turned off
        if not cfg['mock_mode'] and not cfg.get('abuseipdb_key') and not cfg.get('virustotal_key'):
            cfg['mock_mode'] = True
            flash("Configurations updated. Mock mode enforced because API keys are blank.", "warning")
        else:
            flash("Console configurations committed.", "success")
        
        add_notification('settings', 'var(--primary)', 'Settings Updated', 'Console configurations saved successfully.')
        return redirect(url_for('settings'))
        
    system_info = {
        'platform': platform.system(),
        'os_version': platform.version(),
        'python_version': platform.python_version(),
        'architecture': platform.machine()
    }
    return render_template('settings.html', settings=cfg, system_info=system_info)

# --- RUN APPLICATION ---

import os

if __name__ == '__main__':
    print("[*] Starting Malicious IP Intelligence System...")
    print(f"[*] Base Workspace: {Config.BASE_DIR}")

    port = int(os.environ.get("PORT", Config.PORT))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=Config.DEBUG
    )
