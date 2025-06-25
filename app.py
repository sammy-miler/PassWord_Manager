from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from cryptography.fernet import Fernet
import base64
from hashlib import pbkdf2_hmac
import random
import string
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Configuration
DATABASE = 'passwords.db'
MASTER_KEY_SALT = b'fixed_salt_for_demo'
SECURITY_QUESTIONS = [
    "What was your first pet's name?",
    "What city were you born in?",
    "What's your mother's maiden name?",
    "What was your first school name?",
    "What was your childhood nickname?",
    "What is the name of your favorite teacher?"
]

# Initialize database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                master_password_hash TEXT NOT NULL
            )
        ''')
        # Passwords table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Security questions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_questions (
                user_id INTEGER PRIMARY KEY,
                question1 TEXT NOT NULL,
                answer1_hash TEXT NOT NULL,
                question2 TEXT NOT NULL,
                answer2_hash TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# Security functions
def generate_encryption_key(master_password, salt):
    key = pbkdf2_hmac('sha256', master_password.encode(), salt, 100000, dklen=32)
    return base64.urlsafe_b64encode(key)

def encrypt_password(password, encryption_key):
    fernet = Fernet(encryption_key)
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, encryption_key):
    fernet = Fernet(encryption_key)
    return fernet.decrypt(encrypted_password.encode()).decode()

def generate_strong_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

def hash_answer(answer):
    """Hash security answers to prevent plaintext storage"""
    return generate_password_hash(answer.lower().strip())

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        question1 = request.form.get('security_question1')
        answer1 = request.form.get('security_answer1', '').strip()
        question2 = request.form.get('security_question2')
        answer2 = request.form.get('security_answer2', '').strip()

        # Debug prints
        print(f"\n--- REGISTRATION ATTEMPT ---")
        print(f"Username: {username}")
        print(f"Password: {master_password}")
        print(f"Security Q1: {question1}")
        print(f"Answer1: {answer1}")

        # Validation
        if not all([username, master_password, confirm_password, question1, answer1, question2, answer2]):
            flash('All fields are required', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if master_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if len(master_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        if question1 == question2:
            flash('Please select different security questions', 'error')
            return render_template('register.html', security_questions=SECURITY_QUESTIONS)

        try:
            # Debug password hashing
            print("Generating password hash...")
            master_password_hash = generate_password_hash(master_password)
            print("Hashing security answers...")
            answer1_hash = hash_answer(answer1)
            answer2_hash = hash_answer(answer2)
            
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                print("Creating user...")
                cursor.execute('INSERT INTO users (username, master_password_hash) VALUES (?, ?)', 
                              (username, master_password_hash))
                user_id = cursor.lastrowid
                
                print("Storing security questions...")
                cursor.execute('''INSERT INTO security_questions 
                              (user_id, question1, answer1_hash, question2, answer2_hash)
                              VALUES (?, ?, ?, ?, ?)''',
                              (user_id, question1, answer1_hash, question2, answer2_hash))
                conn.commit()
                print("Registration successful!")
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except sqlite3.IntegrityError as e:
            print(f"Integrity Error: {e}")
            flash('Username already exists', 'error')
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            logger.exception("Registration failed:")  # Logs full traceback
            flash('Registration failed. Please try again.', 'error')
        
        return render_template('register.html', security_questions=SECURITY_QUESTIONS)
    
    return render_template('register.html', security_questions=SECURITY_QUESTIONS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('master_password', '').strip()
        
        print(f"\n--- LOGIN ATTEMPT ---")
        print(f"Username: {username}")
        print(f"Password: {password}")
        
        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.row_factory = sqlite3.Row  # For better column access
                cursor = conn.cursor()
                
                # Debug: Verify user exists
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                if user:
                    print("User found in DB:")
                    print(dict(user))  # Print all user data
                    
                    # Verify password
                    is_password_correct = check_password_hash(user['master_password_hash'], password)
                    print(f"Password match: {is_password_correct}")
                    
                    if is_password_correct:
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['encryption_key'] = generate_encryption_key(password, MASTER_KEY_SALT).decode()
                        
                        print("Login successful! Session data:")
                        print(f"user_id: {session['user_id']}")
                        print(f"username: {session['username']}")
                        print(f"encryption_key set: {'encryption_key' in session}")
                        
                        return redirect(url_for('dashboard'))
                    else:
                        print("Password incorrect")
                else:
                    print("User not found in database")
                
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')
     
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        print("Dashboard: No user_id in session")  # Debug
        return redirect(url_for('login'))
    
    try:
        # Debug session
        print(f"\n--- DASHBOARD ACCESS ---")
        print(f"Session user_id: {session.get('user_id')}")
        print(f"Session username: {session.get('username')}")
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, service, username FROM passwords WHERE user_id = ?', 
                         (session['user_id'],))
            passwords = cursor.fetchall()
            print(f"Found {len(passwords)} passwords")  # Debug
            
        return render_template('dashboard.html', passwords=passwords)
        
    except Exception as e:
        print(f"Dashboard error: {e}")  # Debug
        flash('Error loading dashboard', 'error')
        return redirect(url_for('login'))

@app.route('/generate_password', methods=['POST'])
def generate_password():
    print("\n--- Generate Password Endpoint Hit ---")  # Debug
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug
        
        # Required: Validate all inputs
        length = int(data.get('length', 16))
        if length < 8 or length > 64:
            return jsonify({'error': 'Length must be 8-64'}), 400
            
        password = generate_strong_password(
            length=length,
            include_uppercase=data.get('uppercase', True),
            include_lowercase=data.get('lowercase', True),
            include_digits=data.get('digits', True),
            include_special=data.get('special', True)
        )
        
        print("Generated password:", password)  # Debug
        return jsonify({'password': password})
        
    except Exception as e:
        print("Error:", str(e))  # Debug
        return jsonify({'error': str(e)}), 500
      
@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        service = request.form.get('service', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if not service or not password:
            return render_template('add_password.html', error='Service and password are required')
        
        try:
            encrypted_password = encrypt_password(password, session['encryption_key'])
            
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO passwords (user_id, service, username, encrypted_password, notes)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session['user_id'], service, username, encrypted_password, notes))
                conn.commit()
            
            flash('Password added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            return render_template('add_password.html', error='An error occurred while saving password')
    
    return render_template('add_password.html')

@app.route('/view_password/<int:password_id>')
def view_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT service, username, encrypted_password, notes 
                FROM passwords 
                WHERE id = ? AND user_id = ?
            ''', (password_id, session['user_id']))
            password_data = cursor.fetchone()
        
        if not password_data:
            flash('Password not found', 'error')
            return redirect(url_for('dashboard'))
        
        decrypted_password = decrypt_password(password_data[2], session['encryption_key'])
        
        return render_template('view_password.html', 
                             service=password_data[0],
                             username=password_data[1],
                             password=decrypted_password,
                             notes=password_data[3])
    except Exception as e:
        flash('Error accessing password', 'error')
        return redirect(url_for('logout'))

@app.route('/edit_password/<int:password_id>', methods=['GET', 'POST'])
def edit_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        service = request.form.get('service', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        notes = request.form.get('notes', '').strip()
        
        if not service or not password:
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT service, username, encrypted_password, notes 
                    FROM passwords 
                    WHERE id = ? AND user_id = ?
                ''', (password_id, session['user_id']))
                existing_data = cursor.fetchone()
            
            return render_template('edit_password.html', 
                                 password_id=password_id,
                                 service=existing_data[0],
                                 username=existing_data[1],
                                 password=decrypt_password(existing_data[2], session['encryption_key']),
                                 notes=existing_data[3],
                                 error='Service and password are required')
        
        try:
            encrypted_password = encrypt_password(password, session['encryption_key'])
            
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE passwords 
                    SET service = ?, username = ?, encrypted_password = ?, notes = ?
                    WHERE id = ? AND user_id = ?
                ''', (service, username, encrypted_password, notes, password_id, session['user_id']))
                conn.commit()
            
            flash('Password updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            return render_template('edit_password.html', 
                                 password_id=password_id,
                                 service=service,
                                 username=username,
                                 password=password,
                                 notes=notes,
                                 error='An error occurred while updating password')
    
    # GET request - load existing password data
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT service, username, encrypted_password, notes 
                FROM passwords 
                WHERE id = ? AND user_id = ?
            ''', (password_id, session['user_id']))
            password_data = cursor.fetchone()
        
        if not password_data:
            flash('Password not found', 'error')
            return redirect(url_for('dashboard'))
        
        decrypted_password = decrypt_password(password_data[2], session['encryption_key'])
        
        return render_template('edit_password.html', 
                            password_id=password_id,
                            service=password_data[0],
                            username=password_data[1],
                            password=decrypted_password,
                            notes=password_data[3])
    except Exception as e:
        flash('Error loading password', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete_password/<int:password_id>')
def delete_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', 
                         (password_id, session['user_id']))
            conn.commit()
        
        flash('Password deleted successfully!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Error deleting password', 'error')
        return redirect(url_for('dashboard'))


# Forgot Password Flow
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        
        if not username:
            flash('Username is required', 'error')
            return redirect(url_for('forgot_password'))
        
        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get user's security questions
                cursor.execute('''SELECT question1, question2 
                               FROM security_questions
                               WHERE user_id = (SELECT id FROM users WHERE username = ?)''', 
                               (username,))
                questions = cursor.fetchone()
                
                if questions:
                    session['reset_username'] = username
                    return render_template('answer_questions.html',
                                        question1=questions['question1'],
                                        question2=questions['question2'])
                
                flash('Username not found or no security questions set', 'error')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('forgot_password.html')

@app.route('/verify_answers', methods=['POST'])
def verify_answers():
    if 'reset_username' not in session:
        return redirect(url_for('forgot_password'))
    
    try:
        # Get and clean user answers once
        user_answer1 = request.form.get('answer1', '').strip().lower()
        user_answer2 = request.form.get('answer2', '').strip().lower()
        
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get hashed answers from database
            cursor.execute('''
                SELECT answer1_hash, answer2_hash
                FROM security_questions
                WHERE user_id = (
                    SELECT id FROM users WHERE username = ?
                )
            ''', (session['reset_username'],))
            
            answers = cursor.fetchone()
            
            if not answers:
                flash('No security questions found for this user', 'error')
                return redirect(url_for('forgot_password'))
            
            # Verify hashes - THIS IS THE CRITICAL FIX
            if (check_password_hash(answers['answer1_hash'], user_answer1) and 
                check_password_hash(answers['answer2_hash'], user_answer2)):
                session['verified_for_reset'] = True
                return redirect(url_for('reset_password'))
            else:
                flash('Incorrect security answers', 'error')
            
    except sqlite3.Error as e:
        flash('Database error occurred', 'error')
        print(f"Database error: {e}")
        
    return redirect(url_for('forgot_password'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    # Check if user is verified for reset
    if 'verified_for_reset' not in session:
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        # Get the new password and confirmation
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Get security answers again for verification
        answer1 = request.form.get('security_answer1', '').strip().lower()
        answer2 = request.form.get('security_answer2', '').strip().lower()
        
        # Validate inputs
        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
        elif new_password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            try:
                with sqlite3.connect(DATABASE) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    # Verify security answers again
                    cursor.execute('''
                        SELECT answer1_hash, answer2_hash
                        FROM security_questions
                        WHERE user_id = (
                            SELECT id FROM users WHERE username = ?
                        )
                    ''', (session['reset_username'],))
                    
                    answers = cursor.fetchone()
                    
                    if not answers:
                        flash('Security verification failed', 'error')
                        return redirect(url_for('forgot_password'))
                    
                    if not (check_password_hash(answers['answer1_hash'], answer1) and 
                          check_password_hash(answers['answer2_hash'], answer2)):
                        flash('Incorrect security answers', 'error')
                        return render_template('reset_password.html')
                    
                    # If answers are correct, update password
                    cursor.execute('''
                        UPDATE users 
                        SET master_password_hash = ?
                        WHERE username = ?
                    ''', (generate_password_hash(new_password), 
                          session['reset_username']))
                    conn.commit()
                    
                    # Clear session
                    session.pop('reset_username', None)
                    session.pop('verified_for_reset', None)
                    
                    flash('Password reset successfully! Please login.', 'success')
                    return redirect(url_for('login'))
            
            except Exception as e:
                flash(f'Error: {str(e)}', 'error')
    
    # For GET requests or failed POSTs, show the reset form
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT question1, question2 
            FROM security_questions
            WHERE user_id = (
                SELECT id FROM users WHERE username = ?
            )
        ''', (session['reset_username'],))
        questions = cursor.fetchone()
    
    return render_template('reset_password.html',
                         question1=questions['question1'],
                         question2=questions['question2'])


# Add this debug route to check your actual table structure
@app.route('/debug_table')
def debug_table():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(security_questions)")
        columns = cursor.fetchall()
        return str(columns)

# Run this ONE-TIME migration script
@app.route('/fix_database')
def fix_database():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        
        # Backup old table if exists
        cursor.execute("ALTER TABLE security_questions RENAME TO old_security_questions")
        
        # Create new table with correct schema
        cursor.execute('''CREATE TABLE security_questions (
            user_id INTEGER PRIMARY KEY,
            question1 TEXT NOT NULL,
            answer1 TEXT NOT NULL,
            question2 TEXT NOT NULL,
            answer2 TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        ''')
        
        # Copy data if needed
        try:
            cursor.execute('''INSERT INTO security_questions 
                           SELECT * FROM old_security_questions''')
        except:
            pass
            
        conn.commit()
    return "Database fixed"




if __name__ == '__main__':
    init_db()
    app.run(debug=True)