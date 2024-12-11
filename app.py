from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
import pymysql
import config
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import traceback
import re
from datetime import datetime
import functools
import time
import secrets

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

def performance_monitor(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()

        logging.info(f"Function {func.__name__} took {end_time - start_time:.4f} seconds")
        return result
    return wrapper

def timed_lru_cache(seconds=300, maxsize=128):
    def decorator(func):
        cache = {}
        cache_expiration = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            current_time = time.time()

            if key in cache and current_time < cache_expiration.get(key, 0):
                return cache[key]

            result = func(*args, **kwargs)
            cache[key] = result
            cache_expiration[key] = current_time + seconds

            if len(cache) > maxsize:
                oldest_key = min(cache_expiration, key=cache_expiration.get)
                del cache[oldest_key]
                del cache_expiration[oldest_key]

            return result
        return wrapper
    return decorator

def get_db_connection():
    try:
        return pymysql.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            charset='utf8mb4',
            connect_timeout=10,
            read_timeout=10,
            write_timeout=10
        )
    except pymysql.MySQLError as e:
        logging.error(f"Database connection error: {e}")
        return None

@performance_monitor
def load_messages(page=1, per_page=50):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            offset = (page - 1) * per_page

            query = '''
            SELECT id, content, username
            FROM messages
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            '''
            cursor.execute(query, (per_page, offset))
            messages = cursor.fetchall()

            for message in messages:
                if contains_blacklisted_word(message['content']):
                    message['content'] = '[Message removed]'

            cursor.execute('SELECT COUNT(*) as total FROM messages')
            total_messages = cursor.fetchone()['total']

            return {
                'messages': messages,
                'total_pages': (total_messages + per_page - 1) // per_page
            }
    finally:
        conn.close()

@performance_monitor
@timed_lru_cache(seconds=300)
def get_cached_user_stats(username):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT
                    COUNT(*) as message_count,
                    MAX(id) as last_message_id,
                    (SELECT fake_money FROM users WHERE username = %s) as fake_money
                FROM messages
                WHERE username = %s
            ''', (username, username))
            return cursor.fetchone()
    finally:
        conn.close()

@app.route('/profile')
def profile():
    username = session.get('username')

    if not username:
        return redirect(url_for('login'))

    user_stats = get_cached_user_stats(username)

    user = {
        'username': username,
        'fake_money': user_stats['fake_money'] if user_stats else 0,
        'messages_count': user_stats['message_count'] if user_stats else 0
    }

    return render_template('profile.html', user=user, now=datetime.now())

@performance_monitor
@timed_lru_cache(seconds=300)
def get_top_users(limit=10):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT username, fake_money
                FROM users
                ORDER BY fake_money DESC
                LIMIT %s
            ''', (limit,))
            return cursor.fetchall()
    finally:
        conn.close()

@app.route('/leaderboard')
def leaderboard():
    leaderboard_data = get_top_users()

    leaderboard_dict = {
        index + 1: {'username': data['username'], 'fake_money': data['fake_money']}
        for index, data in enumerate(leaderboard_data)
    }

    return render_template('leaderboard.html', leaderboard_data=leaderboard_dict)

@app.route('/poll_messages', methods=['GET'])
def poll_messages():
    messages = load_messages()
    return jsonify({'messages': messages})

#beta html
@app.route('/video_beta')
def video_beta():
    return render_template('beta/video_beta.html')

#blog html

@app.route('/blog')
def blog():
    return render_template('blog/blog.html')

@app.route('/v104')
def v104():
    return render_template('blog/v104.html')

@app.route('/going_forward')
def going_forward():
    return render_template('blog/going_forward.html')

@app.route('/bugs_fixed')
def bugs_fixed():
    return render_template('blog/bugs_fixed.html')

@app.route('/Planned_Updates')
def Planned_Updates():
    return render_template('blog/Planned_Updates.html')

@app.route('/FAQ')
def FAQ():
    return render_template('blog/FAQ.html')

@app.route('/v102')
def v102():
    return render_template('blog/v102.html')

@app.route('/v103')
def v103():
    return render_template('blog/v103.html')

@app.route('/privacy')
def privacy():
    return render_template('blog/privacy.html')

#suggestions html
@app.route('/suggestions')
def suggestions():
    return render_template('suggestions.html')

@app.route('/submit_suggestion', methods=['POST'])
def submit_suggestion():

    suggestion = request.form['suggestion']


    with open('/home/hutcch/chatroom/suggestionstore/suggestions.txt', 'a') as f:
        f.write(suggestion + '\n')

    return "Thank you for your suggestion! <a href='/'>Go back</a>"

@app.route('/search_profile', methods=['GET'])
def search_profile():
    username = request.args.get('username')

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username, fake_money FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()

            cursor.execute("SELECT COUNT(*) as messages_count FROM messages WHERE username = %s", (username,))
            message_count_data = cursor.fetchone()

            if user_data:
                user = {
                    'username': user_data['username'],
                    'fake_money': user_data['fake_money'],
                    'messages_count': message_count_data['messages_count']
                }
            else:
                user = None


            now = datetime.now()


            return render_template('profile.html', user=user, now=now)
    except pymysql.MySQLError as e:
        logging.error(f"Error searching profile data: {e}")
        return "An error occurred while searching for the profile.", 500
    finally:
        connection.close()

def register_user(username, password):
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO users (username, password_hash)
                VALUES (%s, %s)
            ''', (username, hashed_password))
            conn.commit()
    finally:
        conn.close()

def verify_user_credentials(username, password):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT password_hash FROM users WHERE username = %s', (username,))
            result = cursor.fetchone()
            if result and check_password_hash(result['password_hash'], password):
                return True
    finally:
        conn.close()
    return False

def add_fake_money_column():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:

            cursor.execute("SHOW COLUMNS FROM users LIKE 'fake_money';")
            result = cursor.fetchone()

            if result:
                print("Column 'fake_money' already exists.")
            else:

                add_column_query = """
                    ALTER TABLE users
                    ADD COLUMN fake_money INT DEFAULT 0;
                """
                cursor.execute(add_column_query)
                connection.commit()
                print("Column 'fake_money' added successfully.")
    except pymysql.MySQLError as e:
        print("Error adding column:", e)
    finally:
        connection.close()


add_fake_money_column()

def get_fake_money(username):

    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT fake_money FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()

        if result:
            return result['fake_money']
        else:
            return 0
    else:
        return 0

@app.route('/games')
def games():
    username = session.get('username', None)
    if username:
        fake_money = get_fake_money(username)
        return render_template('games.html', username=username, fake_money=fake_money)
    else:
        return redirect(url_for('login'))

@app.route('/update_fake_money', methods=['POST'])
def update_fake_money():
    if 'username' in session:
        data = request.get_json()
        fake_money = data['fake_money']
        username = session['username']

        update_fake_money_in_db(username, fake_money)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'failure', 'message': 'User not logged in'})

def update_fake_money_in_db(username, fake_money):

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET fake_money = %s WHERE username = %s", (fake_money, username))
    connection.commit()
    cursor.close()
    connection.close()

@app.route('/update_score', methods=['POST'])
def update_score():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 401

    username = session['username']
    score = request.form['score']

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('''
                INSERT INTO leaderboard (username, score)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE score = GREATEST(score, %s)
            ''', (username, score, score))
            conn.commit()
    finally:
        conn.close()

    return jsonify({'status': 'success', 'message': 'Score updated successfully'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verify_user_credentials(username, password):
            session['username'] = username
            return redirect(url_for('index_page'))
        else:
            return "Invalid credentials", 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                if user:
                    return "Username already exists", 400

                register_user(username, password)
                return redirect(url_for('login'))
        finally:
            conn.close()

    return render_template('register.html')


def contains_blacklisted_word(message):
    for word in config.BLACKLIST:

        if re.search(r'\b' + re.escape(word) + r'\b', message, re.IGNORECASE):
            return True
    return False

UPLOAD_FOLDER = '/home/hutcch/chatroom/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/images/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image part'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'image_url': f'/images/{filename}'})

def load_blacklist(file_path):
    try:
        with open(file_path, 'r') as file:

            blacklist = [line.strip().lower() for line in file.readlines()]
        return blacklist
    except Exception as e:
        logging.error(f"Error loading blacklist from {file_path}: {e}")
        return []


BLACKLIST = load_blacklist('blacklist.txt')

def contains_blacklisted_word(message):
    for word in BLACKLIST:

        if re.search(r'\b' + re.escape(word) + r'\b', message, re.IGNORECASE):
            return True
    return False

def delete_message(message_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('DELETE FROM messages WHERE id = %s', (message_id,))
            conn.commit()
            if cursor.rowcount == 0:
                logging.warning(f"Message with ID {message_id} not found.")
            else:
                logging.info(f"Message with ID {message_id} deleted.")
    except Exception as e:
        logging.error(f"Error deleting message: {e}")
        conn.rollback()
    finally:
        conn.close()


def load_messages():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT id, content, username FROM messages ORDER BY id ASC')
            messages = cursor.fetchall()


            for message in messages:
                if contains_blacklisted_word(message['content']):
                    message['content'] = '[Message removed for inappropriate content]'
    finally:
        conn.close()
    return messages

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
    return render_template('admin/admin_chat.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

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

    return render_template('admin/admin.html')

@app.route('/image_viewer')
def image_viewer():
    return render_template('image_viewer.html')

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


@app.route('/admin/chat', methods=['GET', 'POST'])
def admin_chat():

    if not session.get('is_admin'):
        return redirect(url_for('index_page'))

    if request.method == 'POST':
        message_content = request.json.get('message')
        if message_content:
            save_message(message_content, 'System')
            return jsonify({'status': 'success'})


    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        messages = load_messages()
        return jsonify({'messages': messages})


    messages = load_messages()
    return render_template('admin/admin_chat.html', messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message_content = data.get('message')
    username = session.get('username', 'Guest')


    if len(message_content) > 1000:
        return jsonify({'status': 'error', 'message': 'Message exceeds the 1000 character limit'}), 400


    if contains_blacklisted_word(message_content):
        return jsonify({'status': 'error', 'message': 'Your message contains inappropriate words.'}), 400


    if message_content:
        save_message(message_content, username)


        return jsonify({'status': 'success', 'message': f'{username}: {message_content}'})
    else:
        return jsonify({'status': 'error', 'message': 'No message content provided'}), 400


def save_message(content, username=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'INSERT INTO messages (content, username) VALUES (%s, %s)',
                (content, username)
            )

            message_id = cursor.lastrowid
        conn.commit()
        return message_id
    finally:
        conn.close()

@app.route('/admin/delete_message', methods=['POST'])
def delete_message_route():
    if request.is_json:
        data = request.get_json()
        message_id = data.get('message_id')

        if message_id:
            try:

                delete_message(message_id)
                return jsonify({'status': 'success', 'message': 'Message deleted successfully.'})
            except Exception as e:
                logging.error(f"Failed to delete message {message_id}: {e}")
                return jsonify({'status': 'error', 'message': 'Error deleting message.'}), 500
        else:
            return jsonify({'status': 'error', 'message': 'No message ID provided.'}), 400
    else:
        return jsonify({'status': 'error', 'message': 'Invalid request format. Expected JSON.'}), 400


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index_page'))

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)
