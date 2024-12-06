from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
import pymysql

app = Flask(__name__)

UPLOAD_FOLDER = '/home/hutcch/chatroom/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/images/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


if __name__ == '__main__':
    import os
    debug_mode = os.getenv('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode)
