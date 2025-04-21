from flask import Flask, render_template, request, redirect, url_for, g, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Замените на случайный секретный ключ
DATABASE = 'users.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('''
                SELECT * FROM users 
                WHERE username = ? OR email = ?
            ''', (username, email))

            if cursor.fetchone():
                return render_template('register.html', error='Пользователь уже существует!')

            cursor.execute('''
                INSERT INTO users (username, email, password)
                VALUES (?, ?, ?)
            ''', (username, email, password))

            db.commit()
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            db.rollback()
            return render_template('register.html', error=f'Ошибка: {str(e)}')
        finally:
            cursor.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('''
                SELECT * FROM users 
                WHERE username = ?
            ''', (username,))

            user = cursor.fetchone()

            if user and check_password_hash(user[3], password):
                session['user'] = {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2]
                }
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Неверные учетные данные')
        finally:
            cursor.close()

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)