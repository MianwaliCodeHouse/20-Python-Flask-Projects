from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
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
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        con = sqlite3.connect('users.db')
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if user and check_password_hash(user[2], password):
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Login failed. Check your email and password.", "danger")

        con.close()

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
