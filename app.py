from flask import Flask, request, session, redirect, render_template
from sqlalchemy import create_engine, text
import bcrypt
import logging
from logging.handlers import SysLogHandler
import socket
import re

# Set up Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  

# Set up SQLAlchemy connection
engine = create_engine("mysql+pymysql://siemuser:StrongPassword!@10.10.10.4/siem_project")

# === Syslog Logging Setup ===
syslog_handler = SysLogHandler(address='/dev/log')  # local syslog on Linux
formatter = logging.Formatter('%(asctime)s %(hostname)s app[%(process)d]: %(message)s',
                              datefmt='%b %d %H:%M:%S')

hostname = socket.gethostname()
formatter.default_msec_format = '%s.%03d'
syslog_handler.setFormatter(logging.Formatter(f'%(asctime)s {hostname} flask_app: %(message)s'))

logger = logging.getLogger()
logger.setLevel(logging.INFO)   
logger.addHandler(syslog_handler)

# Example log to confirm startup
logger.info("Flask app started and syslog handler is configured.")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Server-side password validation
        if len(password) < 8 or not re.search(r'[^a-zA-Z0-9]', password):
            logger.warning(f"Signup failed due to weak password for user: {username}")
            return "Password must be at least 8 characters long and include a special character."

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        sql = text("INSERT INTO users (username, password) VALUES (:username, :password)")
        with engine.connect() as connection:
            connection.execute(sql, {"username": username, "password": hashed_password.decode('utf-8')})
            connection.commit()

        logger.info(f"New user signed up: {username}")
        return redirect('/login')
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Inject vulnerability in the username field ONLY
        raw_sql = f"SELECT * FROM users WHERE username = '{username}'"
        with engine.connect() as connection:
           result = connection.execute(text(raw_sql)).mappings().fetchone()
            
        #sql = text("SELECT * FROM users WHERE username = :username")
        #with engine.connect() as connection:
            #result = connection.execute(sql, {"username": username}).mappings().fetchone()

        if result:
            stored_hash = result['password'].encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['user_id'] = result['id']
                session['username'] = username
                logger.info(f"User logged in: {username}")
                return redirect('/form')

        logger.warning(f"Failed login attempt: {username}")
        return "INVALID CREDENTIALS"
    return render_template('login.html')

@app.route('/form', methods=['GET', 'POST'])
def form():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        message = request.form['data']

        sql = text("INSERT INTO messages (user_id, message) VALUES (:user_id, :message)")
        with engine.connect() as connection:
            connection.execute(sql, {"user_id": session['user_id'], "message": message})
            connection.commit()

        logger.info(f"Message submitted by user_id={session['user_id']}: {message}")
        return "Form Submitted!"
    return render_template('form.html')

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    logger.info(f"User logged out: {username}")
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
