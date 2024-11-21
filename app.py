from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import pymysql
import config
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import traceback

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = '' 


def get_db_connection():
    try:
        return pymysql.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.MySQLError as e:
        logging.error(f"Database connection error: {e}")
        return None


@app.before_first_request
def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    content TEXT NOT NULL,
                    username VARCHAR(50) DEFAULT NULL
                )
            ''')

            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL
                )
            ''')

            
            cursor.execute('SELECT COUNT(*) as count FROM admins')
            if cursor.fetchone()['count'] == 0:
                hashed_password = generate_password_hash(config.ADMIN_PASSWORD)
                cursor.execute(
                    'INSERT INTO admins (username, password_hash) VALUES (%s, %s)',
                    (config.ADMIN_USERNAME, hashed_password)
                )
        conn.commit()
    finally:
        conn.close()


def load_messages():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT content, username FROM messages ORDER BY id ASC')
            messages = cursor.fetchall()
    finally:
        conn.close()
    return messages


def save_message(content, username=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'INSERT INTO messages (content, username) VALUES (%s, %s)',
                (content, username)
            )
        conn.commit()
    finally:
        conn.close()


def verify_admin_credentials(username, password):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT password_hash FROM admins WHERE username = %s', (username,))
            result = cursor.fetchone()
            if result and check_password_hash(result['password_hash'], password):
                return True
    finally:
        conn.close()
    return False

@app.route('/admin_chat')
def admin_chat_page():
    return render_template('admin_chat.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verify_admin_credentials(username, password):
            session['is_admin'] = True
            session['username'] = 'System'  
            return redirect(url_for('admin_chat'))  

        return "Invalid credentials", 401 

    return render_template('admin.html')  

@app.route('/about')
def about():
    try:
        return render_template('about.html')
    except Exception as e:
        logging.error(f"Error rendering about page: {traceback.format_exc()}")
        return "An internal error has occurred!", 500

@app.route('/news')
def news():
    try:
        return render_template('news.html')
    except Exception as e:
        logging.error(f"Error rendering news page: {traceback.format_exc()}")
        return "An internal error has occurred!", 500

@app.route('/chatroom')
def chatroom_page():
    return render_template('chatroom.html')

@app.route('/index', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def index_page():
    if request.method == 'POST':
        message_content = request.form['message']
        username = session.get('username', 'Guest')
        if message_content:
            save_message(message_content, username)
            return redirect(url_for('index'))  

    messages = load_messages()  
    return render_template('index.html', messages=messages)  



@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()  
    message_content = data.get('message')
    username = session.get('username', 'Guest') 

    
    if len(message_content) > 1000:
        return jsonify({'status': 'error', 'message': 'Message exceeds the 1000 character limit'}), 400

    if message_content:
        save_message(message_content, username)  

        
        return jsonify({'status': 'success', 'message': f'{username}: {message_content}'})
    else:
        return jsonify({'status': 'error', 'message': 'No message content provided'}), 400


@app.route('/admin/chat', methods=['GET', 'POST'])
def admin_chat():
    
    if not session.get('is_admin'):
        return redirect(url_for('index_page'))  

    if request.method == 'POST':
        message_content = request.form['message']
        if message_content:
            save_message(message_content, 'System')  
            return redirect(url_for('admin_chat'))

    messages = load_messages()
    return render_template('admin_chat.html', messages=messages)


@app.route('/logout')
def logout():
    session.clear()  
    return redirect(url_for('index_page'))  


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)
