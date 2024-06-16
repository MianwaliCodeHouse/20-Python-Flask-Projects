from flask import Flask, render_template, request, redirect, url_for, flash,session
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Database setup
def init_sqlite_db():
    conn = sqlite3.connect('users.db')
    print("Opened database successfully")

    conn.execute('CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT, password TEXT)')
    print("Table created successfully")
    conn.close()

init_sqlite_db()
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to view this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def not_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            flash("You need to be logout to view this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
@not_login
def register():
    con = None  # Initialize con to None
    if request.method == 'POST':
        try:
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']

            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

            con = sqlite3.connect('users.db')
            cur = con.cursor()
            cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
            con.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            if con:
                con.rollback()
            flash(f"Error occurred: {str(e)}", "danger")
        
        finally:
            if con:
                con.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@not_login
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        con = sqlite3.connect('users.db')
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['email'] = user[1]
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Check your email and password.", "danger")

        con.close()

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
