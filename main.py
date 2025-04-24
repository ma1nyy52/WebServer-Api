from flask import Flask, render_template, request, redirect, url_for, g, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
DATABASE = 'users.db'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")  # Включаем поддержку внешних ключей
    return db


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        try:
            # Создаем таблицу пользователей
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    security_question TEXT NOT NULL,
                    security_answer TEXT NOT NULL
                )
            ''')

            # Создаем таблицу комнат
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code TEXT UNIQUE NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Создаем таблицу участников
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS participants (
                    user_id INTEGER,
                    room_id INTEGER,
                    PRIMARY KEY (user_id, room_id),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
                )
            ''')

            # Добавляем тестовые комнаты
            for code in ['ROOM1', 'ROOM2', 'ROOM3']:
                cursor.execute('''
                    INSERT OR IGNORE INTO rooms (code) VALUES (?)
                ''', (code,))

            db.commit()
        except Exception as e:
            print(f"Ошибка при инициализации БД: {str(e)}")
        finally:
            cursor.close()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/join-room', methods=['POST'])
def join_room():
    if 'user' not in session:
        return redirect(url_for('login'))

    code = request.form['room_code'].strip().upper()
    db = get_db()
    cursor = db.cursor()

    try:
        # Проверяем существование комнаты
        cursor.execute('SELECT id FROM rooms WHERE code = ?', (code,))
        room = cursor.fetchone()

        if not room:
            return render_template('index.html',
                                   user=session.get('user'),
                                   error='Комната с таким кодом не существует')

        room_id = room[0]
        user_id = session['user']['id']

        # Добавляем участника
        try:
            cursor.execute('''
                INSERT INTO participants (user_id, room_id)
                VALUES (?, ?)
            ''', (user_id, room_id))
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return render_template('index.html',
                                   user=session.get('user'),
                                   info='Вы уже в этой комнате')

        return redirect(url_for('view_room', code=code))

    except Exception as e:
        db.rollback()
        return render_template('index.html',
                               user=session.get('user'),
                               error=f'Ошибка: {str(e)}')
    finally:
        cursor.close()


# Главная страница
@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        question = request.form['security_question']
        answer = request.form['security_answer']

        if not all([username, email, password, question, answer]):
            return render_template('register.html',
                                   error='Все поля обязательны для заполнения')

        hashed_password = generate_password_hash(password)
        hashed_answer = generate_password_hash(answer.lower().strip())

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('''
                INSERT INTO users 
                (username, email, password, security_question, security_answer)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, hashed_password, question, hashed_answer))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html',
                                   error='Пользователь с таким именем или email уже существует')
        finally:
            cursor.close()

    return render_template('register.html')


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user[3], password):
                session['user'] = {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2]
                }
                return redirect(url_for('index'))
            return render_template('login.html', error='Неверные учетные данные')
        finally:
            cursor.close()

    return render_template('login.html')


# Выход
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# Восстановление пароля
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        answer = request.form['security_answer']
        new_password = request.form['new_password']

        db = get_db()
        cursor = db.cursor()

        try:
            cursor.execute('''
                SELECT * FROM users 
                WHERE username = ? AND email = ?
            ''', (username, email))

            user = cursor.fetchone()

            if user and check_password_hash(user[5], answer.lower().strip()):
                hashed_password = generate_password_hash(new_password)
                cursor.execute('''
                    UPDATE users 
                    SET password = ? 
                    WHERE id = ?
                ''', (hashed_password, user[0]))
                db.commit()
                return render_template('login.html',
                                       success='Пароль успешно изменен')

            return render_template('forgot-password.html',
                                   error='Неверные данные или ответ на вопрос')
        finally:
            cursor.close()

    return render_template('forgot-password.html')


# Смена пароля
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('''
            SELECT security_question 
            FROM users 
            WHERE id = ?
        ''', (session['user']['id'],))

        question = cursor.fetchone()[0]

        if request.method == 'POST':
            old_password = request.form['old_password']
            answer = request.form['security_answer']
            new_password = request.form['new_password']

            cursor.execute('''
                SELECT password, security_answer 
                FROM users 
                WHERE id = ?
            ''', (session['user']['id'],))

            user_data = cursor.fetchone()

            if not check_password_hash(user_data[0], old_password):
                return render_template('change-password.html',
                                       question=question,
                                       error='Неверный старый пароль')

            if not check_password_hash(user_data[1], answer.lower().strip()):
                return render_template('change-password.html',
                                       question=question,
                                       error='Неверный ответ на вопрос')

            hashed_password = generate_password_hash(new_password)
            cursor.execute('''
                UPDATE users 
                SET password = ? 
                WHERE id = ?
            ''', (hashed_password, session['user']['id']))

            db.commit()
            return render_template('index.html',
                                   message='Пароль успешно изменен')

        return render_template('change-password.html', question=question)

    finally:
        cursor.close()


@app.route('/room/<code>')
def view_room(code):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    try:
        # Проверяем существование комнаты
        cursor.execute('''
            SELECT r.code, u.username 
            FROM rooms r
            JOIN participants p ON r.id = p.room_id
            JOIN users u ON p.user_id = u.id
            WHERE r.code = ?
        ''', (code,))

        participants = cursor.fetchall()

        if not participants:
            return render_template('index.html',
                                   user=session.get('user'),
                                   error='Комната не существует или пуста')

        return render_template('room.html',
                                   room_code=code,
                                   participants=[p[1] for p in participants],
                                   user=session.get('user'))

    except Exception as e:
        return render_template('index.html',
                               user=session.get('user'),
                               error=f'Ошибка: {str(e)}')
    finally:
        cursor.close()


if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
