from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory # Import send_from_directory
import pymysql
import config
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import traceback
import re

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = 'no'  # Replace with a strong, random secret key

# Function to connect to the database
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

# Initialize the database only on the first request
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

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS leaderboard (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    score INT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            # Check if the column already exists
            cursor.execute("SHOW COLUMNS FROM users LIKE 'fake_money';")
            result = cursor.fetchone()

            if result:
                print("Column 'fake_money' already exists.")
            else:
                # SQL query to add the column
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

# Call the function
add_fake_money_column()

def get_fake_money(username):
    # Get database connection using the function
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("SELECT fake_money FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        cursor.close()
        connection.close()

        if result:
            return result['fake_money']  # Return the fake money value from the result
        else:
            return 0  # Default to 0 if the user is not found
    else:
        return 0  # If connection fails, return 0 as a fallback

@app.route('/games')
def games():
    username = session.get('username', None)  # Assuming you're using session to store the username
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
        # Update the user's fake money balance in the database
        update_fake_money_in_db(username, fake_money)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'failure', 'message': 'User not logged in'})

def update_fake_money_in_db(username, fake_money):
    # This should update the user's fake money in the database
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET fake_money = %s WHERE username = %s", (fake_money, username))
    connection.commit()
    cursor.close()
    connection.close()


@app.route('/leaderboard')
def leaderboard():
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username, fake_money FROM users ORDER BY fake_money DESC LIMIT 10")
            leaderboard_data = cursor.fetchall()

            # Convert list of tuples to a dictionary with ranks as keys
            leaderboard_data = {index + 1: {'username': data['username'], 'fake_money': data['fake_money']}
                                 for index, data in enumerate(leaderboard_data)}

            return render_template('leaderboard.html', leaderboard_data=leaderboard_data)
    except pymysql.MySQLError as e:
        print(f"Error fetching leaderboard data: {e}")
        return "Error fetching leaderboard data", 500
    finally:
        connection.close()

@app.route('/update_score', methods=['POST'])
def update_score():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 401

    username = session['username']
    score = request.form['score']  # You could get this value from a challenge or game logic

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
            session['username'] = username  # Store username in session
            return redirect(url_for('index_page'))  # Redirect to main page after successful login
        else:
            return "Invalid credentials", 401  # Return unauthorized if credentials are wrong

    return render_template('login.html')  # Render login page

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if the username already exists
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
                user = cursor.fetchone()
                if user:
                    return "Username already exists", 400  # Return error if username exists
                # Register the user if not exists
                register_user(username, password)
                return redirect(url_for('login'))  # Redirect to login after successful registration
        finally:
            conn.close()

    return render_template('register.html')  # Render registration page

# Function to check if message contains blacklisted words
def contains_blacklisted_word(message):
    for word in config.BLACKLIST:
        # Check if any blacklisted word is found in the message (case insensitive)
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

        filename = secure_filename(file.filename)  # Import secure_filename from werkzeug.utils
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'image_url': f'/images/{filename}'})

def load_blacklist(file_path):
    try:
        with open(file_path, 'r') as file:
            # Read all lines and strip newline characters, then return the list
            blacklist = [line.strip().lower() for line in file.readlines()]
        return blacklist
    except Exception as e:
        logging.error(f"Error loading blacklist from {file_path}: {e}")
        return []

# Load the blacklist from the text file at startup
BLACKLIST = load_blacklist('blacklist.txt')

def contains_blacklisted_word(message):
    for word in BLACKLIST:
        # Check if any blacklisted word is found in the message (case insensitive)
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
        conn.rollback()  # Rollback in case of error
    finally:
        conn.close()

# Load messages from the database
def load_messages():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute('SELECT id, content, username FROM messages ORDER BY id ASC')
            messages = cursor.fetchall()

            # Filter out blacklisted words from messages
            for message in messages:
                if contains_blacklisted_word(message['content']):
                    message['content'] = '[Message removed for inappropriate content]'
    finally:
        conn.close()
    return messages

# Verify admin credentials
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
            session['username'] = 'System'  # System username for admin messages
            return redirect(url_for('admin_chat'))  # Redirect to the admin chat page

        return "Invalid credentials", 401  # Return unauthorized if credentials are wrong

    return render_template('admin.html')  # Render admin login page

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
    if 'username' not in session:  # Check if the user is logged in
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    return render_template('chatroom.html')

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
            return redirect(url_for('index'))  # Redirect to the index page after message is sent

    messages = load_messages()  # Load all messages from the database
    return render_template('index.html', messages=messages)  # Render the index template

# Admin chatroom page
@app.route('/admin/chat', methods=['GET', 'POST'])
def admin_chat():
    # Only allow admin to access this page
    if not session.get('is_admin'):
        return redirect(url_for('index_page'))  # Redirect to main chatroom if not admin

    if request.method == 'POST':
        message_content = request.json.get('message')  # Get message content from the AJAX request
        if message_content:
            save_message(message_content, 'System')  # Save the message with 'System' as the username
            return jsonify({'status': 'success'})  # Return success for AJAX

    # Handle GET requests for AJAX polling
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        messages = load_messages()
        return jsonify({'messages': messages})  # Return the messages as JSON

    # Regular GET request, render the page
    messages = load_messages()
    return render_template('admin_chat.html', messages=messages)

@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()  # Get JSON data from the request
    message_content = data.get('message')
    username = session.get('username', 'Guest')  # Default to 'Guest' if no user is logged in

    # Check if the message length exceeds 1000 characters
    if len(message_content) > 1000:
        return jsonify({'status': 'error', 'message': 'Message exceeds the 1000 character limit'}), 400

    # Check if the message contains any blacklisted words
    if contains_blacklisted_word(message_content):
        return jsonify({'status': 'error', 'message': 'Your message contains inappropriate words.'}), 400

    # Save message to the database if it's clean
    if message_content:
        save_message(message_content, username)  # Save message to the database

        # Return a JSON response to confirm the message was saved
        return jsonify({'status': 'success', 'message': f'{username}: {message_content}'})
    else:
        return jsonify({'status': 'error', 'message': 'No message content provided'}), 400

# Modified save_message to return the message ID
def save_message(content, username=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                'INSERT INTO messages (content, username) VALUES (%s, %s)',
                (content, username)
            )
            # Get the last inserted ID (message_id)
            message_id = cursor.lastrowid
        conn.commit()
        return message_id  # Return the ID of the new message
    finally:
        conn.close()

# Route to poll for new messages (AJAX)
@app.route('/poll_messages', methods=['GET'])
def poll_messages():
    messages = load_messages()
    return jsonify({'messages': messages})  # Return messages as JSON

# Your existing delete message route
@app.route('/admin/delete_message', methods=['POST'])
def delete_message_route():
    if request.is_json:
        data = request.get_json()
        message_id = data.get('message_id')

        if message_id:
            try:
                # Call the function to delete the message from the database
                delete_message(message_id)
                return jsonify({'status': 'success', 'message': 'Message deleted successfully.'})
            except Exception as e:
                logging.error(f"Failed to delete message {message_id}: {e}")
                return jsonify({'status': 'error', 'message': 'Error deleting message.'}), 500
        else:
            return jsonify({'status': 'error', 'message': 'No message ID provided.'}), 400
    else:
        return jsonify({'status': 'error', 'message': 'Invalid request format. Expected JSON.'}), 400

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for('index_page'))  # Redirect to main chatroom (index)

# Function to run the Flask app
if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)
