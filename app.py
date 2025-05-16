from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, g, send_from_directory
from io import BytesIO
import random
import string
import time
import socket
import smtplib
import dns.resolver
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session, relationship
import pandas as pd
import concurrent.futures
from sqlalchemy import desc
from functools import wraps
import re
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
from flask_cors import CORS
app = Flask(__name__)
CORS(app)

# Status codes for SMTP responses
INVALID_MAILBOX_STATUS = [550]
VALID_MAILBOX_STATUS = [250, 251]

# Database setup
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(String(20), primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(256))  # Increased from 128 to 256
    api_token = Column(String(256))  # Increased from 128 to 256
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False)
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # Generate ID if not provided
        if not self.id:
            self.generate_id()
    
    def generate_id(self):
        """Generate a random numeric ID between 10 and 20 digits"""
        length = random.randint(10, 20)  # Random length between 10 and 20
        self.id = ''.join([str(random.randint(0, 9)) for _ in range(length)])
        
        # Ensure ID is unique
        session = Session()
        while session.query(User).filter_by(id=self.id).first():
            self.id = ''.join([str(random.randint(0, 9)) for _ in range(length)])
        session.close()
    
    def validate_id(self, id):
        """Validate that ID is numeric and between 10-20 digits"""
        if not re.match(r'^\d{10,20}$', str(id)):
            raise ValueError("ID must be 10-20 numeric digits")
        return True
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_token(self):
        self.api_token = secrets.token_urlsafe(32)
        return self.api_token

class AvailableAccount(Base):
    __tablename__ = 'available_accounts'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    check_date = Column(String)
    user_id = Column(String(20), ForeignKey('users.id'))
    user = relationship('User', backref='available_accounts')

class GeneratedAccount(Base):
    __tablename__ = 'generated_accounts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    check_date = Column(DateTime, default=datetime.now)
    user_id = Column(String(20), ForeignKey('users.id'))
    user = relationship('User', backref='generated_accounts')

# Initialize database
engine = create_engine('sqlite:///gmail_accounts.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = scoped_session(Session)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if ' ' in auth_header:
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': 'API token is missing'}), 401
            
        current_user = db_session.query(User).filter_by(api_token=token).first()
        
        if not current_user:
            return jsonify({'error': 'Invalid API token'}), 401
            
        g.current_user = current_user
        return f(*args, **kwargs)
    return decorated

def generate_random_password(length=12, include_uppercase=True, include_lowercase=True, 
                           include_digits=True, include_special=True, special_chars="!@#$%^&*"):
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    
    char_pool = ""
    requirements = []
    
    if include_uppercase:
        char_pool += string.ascii_uppercase
        requirements.append(lambda p: any(c.isupper() for c in p))
    if include_lowercase:
        char_pool += string.ascii_lowercase
        requirements.append(lambda p: any(c.islower() for c in p))
    if include_digits:
        char_pool += string.digits
        requirements.append(lambda p: any(c.isdigit() for c in p))
    if include_special:
        char_pool += special_chars
        requirements.append(lambda p: any(c in special_chars for c in p))
    
    if not char_pool:
        raise ValueError("At least one character set must be included")
    
    while True:
        password = ''.join(secrets.choice(char_pool) for _ in range(length))
        if all(req(password) for req in requirements):
            return password

def generate_random_username(min_length=6, max_length=15):
    """Generate a random username with letters first followed by numbers."""
    length = random.randint(min_length, max_length)
    
    # Determine how many letters and numbers to use (at least 1 of each)
    min_letters = max(1, length // 2)
    num_letters = random.randint(min_letters, length - 1)
    num_digits = length - num_letters
    
    # Generate letters part
    letters = ''.join(random.choice(string.ascii_lowercase) for _ in range(num_letters))
    
    # Generate digits part
    digits = ''.join(random.choice(string.digits) for _ in range(num_digits))
    
    # Combine letters first then digits
    username = letters + digits
    
    return username

def get_mx_for_domain(domain="gmail.com"):
    """Retrieve the MX record for Gmail with error handling."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted((r.preference, str(r.exchange).rstrip('.')) for r in answers)
        return mx_records[0][1] if mx_records else None
    except Exception as e:
        print(f"Error fetching MX for {domain}: {e}")
        return None

def check_email_availability(email, mx_host):
    """Check if a Gmail address is available via SMTP."""
    try:
        # Reduced timeout to avoid long waits
        with smtplib.SMTP(mx_host, port=25, timeout=3) as smtp:
            smtp.ehlo()
            # Use a valid sender address
            smtp.mail('test@example.com')
            code, response = smtp.rcpt(email)
            
            if code in VALID_MAILBOX_STATUS:
                return False  # Email exists
            elif code in INVALID_MAILBOX_STATUS:
                return True  # Available
            return None  # Unknown status
    except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        print(f"SMTP error checking {email}: {e}")
        return None

def check_email_availability_with_retry(email, mx_host, max_retries=2, delay=2):
    """Try checking email availability with retries."""
    for attempt in range(max_retries):
        result = check_email_availability(email, mx_host)
        if result is not None:
            return result
        
        # Sleep before retry only if not the last attempt
        if attempt < max_retries - 1:
            print(f"Retrying {email} in {delay} seconds...")
            time.sleep(delay)
    
    print(f"Giving up on {email} after {max_retries} attempts")
    return None  # Give up after retries

def try_generate_account(mx_host, user):
    max_attempts = 5
    
    for _ in range(max_attempts):
        username = generate_random_username()
        email = f"{username}@gmail.com"
    
        if (db_session.query(AvailableAccount).filter_by(email=email).first() or 
            db_session.query(GeneratedAccount).filter_by(email=email).first()):
            continue
            
        is_available = check_email_availability_with_retry(email, mx_host)
        
        if is_available:
            password = generate_random_password()
            current_date = datetime.now()
            
            db_account = GeneratedAccount(
                username=username,
                email=email,
                password=password,
                check_date=current_date,
                user_id=user.id,
            )
            db_session.add(db_account)
            db_session.commit()
            
            return {
                'username': username,
                'email': email,
                'password': password,
                'check_date': current_date.strftime("%Y-%m-%d %H:%M:%S"),
                'user_id': user.id,
            }
    
    return None

@app.route('/generate_single', methods=['POST'])
@token_required
def generate_single():
    mx_host = get_mx_for_domain()
    
    if not mx_host:
        return jsonify({'error': 'Failed to get MX record for Gmail. Try again later.'}), 500
    
    account = try_generate_account(mx_host, g.current_user)
    
    if account:
        return jsonify({'account': account})
    else:
        return jsonify({'error': 'Could not find available account after multiple attempts'}), 500

@app.route('/save_account', methods=['POST'])
@token_required
def save_account():
    try:
        account_data = request.get_json()
        if not account_data:
            return jsonify({'error': 'No data provided'}), 400
            
        account_data['user_id'] = g.current_user.id
        
        # Check if this is a generated account
        generated = db_session.query(GeneratedAccount).filter_by(
            email=account_data['email'],
            user_id=g.current_user.id
        ).first()
        
        if generated:
            db_session.delete(generated)
        
        # Check if account already exists in available accounts
        existing = db_session.query(AvailableAccount).filter_by(
            email=account_data['email'],
            user_id=g.current_user.id
        ).first()
        
        if existing:
            return jsonify({'error': 'Account already saved'}), 400
        
        db_account = AvailableAccount(
            username=account_data['username'],
            email=account_data['email'],
            password=account_data['password'],
            check_date=account_data['check_date'],
            user_id=g.current_user.id
        )
        db_session.add(db_account)
        db_session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/saved_accounts')
@token_required
def get_saved_accounts():
    try:
        accounts = db_session.query(AvailableAccount).filter_by(user_id=g.current_user.id).all()
        accounts_data = [{
            'id': account.id,
            'username': account.username,
            'email': account.email,
            'password': account.password,
            'check_date': account.check_date
        } for account in accounts]
        return jsonify({'accounts': accounts_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete/<int:account_id>', methods=['DELETE'])
@token_required
def delete_account(account_id):
    try:
        # Check in available accounts first
        account = db_session.query(AvailableAccount).filter_by(
            id=account_id,
            user_id=g.current_user.id
        ).first()
        
        if account:
            db_session.delete(account)
            db_session.commit()
            return jsonify({'success': True})
            
        # Check in generated accounts if not found in available
        generated = db_session.query(GeneratedAccount).filter_by(
            id=account_id,
            user_id=g.current_user.id
        ).first()
        
        if generated:
            db_session.delete(generated)
            db_session.commit()
            return jsonify({'success': True})
            
        return jsonify({'error': 'Account not found or not owned by user'}), 404
    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/download')
@token_required
def download():
    try:
        saved_accounts = db_session.query(AvailableAccount).filter_by(
            user_id=g.current_user.id
        ).all()
        
        if not saved_accounts:
            return jsonify({'error': 'No accounts found'}), 404
        
        data = {
            'Email': [account.email for account in saved_accounts],
            'Password': [account.password for account in saved_accounts]
        }
        df = pd.DataFrame(data)
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Accounts')
            for column in df:
                column_width = max(df[column].astype(str).map(len).max(), len(column))
                col_idx = df.columns.get_loc(column)
                writer.sheets['Accounts'].set_column(col_idx, col_idx, column_width)
        
        output.seek(0)
        
        gmt6_time = datetime.now(timezone.utc) + timedelta(hours=6)
        timestamp = gmt6_time.strftime("%I-%M-%S-%p-%d-%m-%Y")
        filename = f"gmail_accounts-{timestamp}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generated_accounts')
@token_required
def get_generated_accounts():
    try:
        accounts = db_session.query(GeneratedAccount).filter_by(
            user_id=g.current_user.id
        ).order_by(GeneratedAccount.check_date.desc()).all()
        
        accounts_data = [{
            'id': account.id,
            'username': account.username,
            'email': account.email,
            'password': account.password,
            'check_date': account.check_date.strftime("%Y-%m-%d %H:%M:%S")
        } for account in accounts]
        return jsonify({'accounts': accounts_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cancel_generated', methods=['POST'])
@token_required
def cancel_generated():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        emails_to_delete = data.get('emails', [])
        deleted_count = 0
        
        for email in emails_to_delete:
            account = db_session.query(GeneratedAccount).filter_by(
                email=email,
                user_id=g.current_user.id
            ).first()
            if account:
                db_session.delete(account)
                deleted_count += 1
        
        db_session.commit()
        return jsonify({
            'success': True, 
            'deleted_count': deleted_count
        })
    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/validate-token', methods=['POST'])
def validate_token():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    api_token = data.get('api_token')
    
    if not api_token:
        return jsonify({'error': 'API token is required'}), 400
    
    user = db_session.query(User).filter_by(api_token=api_token).first()
    
    if not user:
        return jsonify({'error': 'Invalid API token'}), 401
    
    return jsonify({
        'message': 'Token is valid',
        'user_id': user.id,
        'username': user.username
    })

@app.route('/account_register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    if db_session.query(User).filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    try:
        user = User(username=username)
        user.set_password(password)
        user.generate_api_token()
        
        db_session.add(user)
        db_session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'api_token': user.api_token,
            'user_id': user.id,
            'username': user.username
        }), 201
    except Exception as e:
        db_session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/account_login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    user = db_session.query(User).filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    return jsonify({
        'message': 'Login successful',
        'api_token': user.api_token,
        'user_id': user.id,
        'username': user.username
    })

@app.route('/<path:path>')
def serve_nextjs(path):
    return send_from_directory('static/nextjs', path)

@app.route('/')
def serve_nextjs_index():
    return send_from_directory('static/nextjs', 'index.html')

@app.route('/login', strict_slashes=False)
def serve_login():
    return send_from_directory('static/nextjs/login', 'index.html')

@app.route('/saved', strict_slashes=False)
def serve_saved():
    return send_from_directory('static/nextjs/saved', 'index.html')

@app.route('/generate_account', strict_slashes=False)
def serve_generate_account():
    return send_from_directory('static/nextjs/generate_account', 'index.html')

@app.route('/register', strict_slashes=False)
def serve_register():
    return send_from_directory('static/nextjs/register', 'index.html')

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)