from flask import Flask, render_template, request, redirect, url_for, session, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
DATABASE = 'users.db'
ADMINS_FILE = 'admins.txt'

# Создаем папку для загрузок
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def load_admins():
    admins = {}
    try:
        with open(ADMINS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    username, password = line.split(':', 1)
                    admins[username] = password
    except Exception as e:
        print(f"Ошибка загрузки admins.txt: {str(e)}")
    return admins

ADMINS = load_admins()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.execute("PRAGMA foreign_keys = ON")
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
                password TEXT NOT NULL,
                security_question TEXT NOT NULL,
                security_answer TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS participants (
                user_id INTEGER,
                room_id INTEGER,
                PRIMARY KEY (user_id, room_id),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(room_id) REFERENCES rooms(id) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                assignment_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                grade INTEGER,
                comment TEXT,
                submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
            )
        ''')

        db.commit()
        cursor.close()

def get_participants(room_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT u.username 
            FROM participants p
            JOIN users u ON p.user_id = u.id
            WHERE p.room_id = ?
        ''', (room_id,))
        participants = cursor.fetchall()
        return [p[0] for p in participants]
    finally:
        cursor.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Маршруты пользователя
@app.route('/')
def index():
    return render_template('index.html',
                           user=session.get('user'),
                           is_admin=session.get('is_admin'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        question = request.form['security_question']
        answer = request.form['security_answer']

        if not all([username, email, password, question, answer]):
            return render_template('register.html', error='Все поля обязательны')

        hashed_pw = generate_password_hash(password)
        hashed_answer = generate_password_hash(answer.lower().strip())

        db = get_db()
        try:
            db.execute('''
                INSERT INTO users 
                (username, email, password, security_question, security_answer)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, hashed_pw, question, hashed_answer))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Пользователь уже существует')
        finally:
            db.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute('''
            SELECT * FROM users WHERE username = ?
        ''', (username,)).fetchone()

        if user and check_password_hash(user[3], password):
            session['user'] = {
                'id': user[0],
                'username': user[1],
                'email': user[2]
            }

            # Проверяем последнюю комнату
            last_room_id = user[6]  # Индекс поля last_room_id

            if last_room_id:
                # Проверяем доступность комнаты
                room_data = db.execute('''
                    SELECT r.code, r.is_closed 
                    FROM rooms r
                    JOIN participants p ON r.id = p.room_id
                    WHERE r.id = ? AND p.user_id = ?
                ''', (last_room_id, user[0])).fetchone()

                if room_data and not room_data[1]:
                    return redirect(url_for('view_room', code=room_data[0]))

            return redirect(url_for('index'))

        return render_template('login.html', error='Неверные данные')

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'user' in session:
        user_id = session['user']['id']
        current_room_id = session['user'].get('current_room_id')

        # Сохраняем последнюю комнату в БД
        db = get_db()
        db.execute('''
            UPDATE users 
            SET last_room_id = ? 
            WHERE id = ?
        ''', (current_room_id, user_id))
        db.commit()
        db.close()

    session.pop('user', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))


# Восстановление и смена пароля
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        answer = request.form['security_answer']
        new_password = request.form['new_password']

        db = get_db()
        user = db.execute('''
            SELECT * FROM users 
            WHERE username = ? AND email = ?
        ''', (username, email)).fetchone()

        if user and check_password_hash(user[5], answer.lower().strip()):
            hashed_pw = generate_password_hash(new_password)
            db.execute('''
                UPDATE users SET password = ? WHERE id = ?
            ''', (hashed_pw, user[0]))
            db.commit()
            return render_template('login.html', success='Пароль изменен')

        return render_template('forgot-password.html', error='Ошибка проверки')

    return render_template('forgot-password.html')


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    question = db.execute('''
        SELECT security_question FROM users WHERE id = ?
    ''', (session['user']['id'],)).fetchone()[0]

    if request.method == 'POST':
        old_pw = request.form['old_password']
        answer = request.form['answer']
        new_pw = request.form['new_password']

        user_data = db.execute('''
            SELECT password, security_answer FROM users WHERE id = ?
        ''', (session['user']['id'],)).fetchone()

        if not check_password_hash(user_data[0], old_pw):
            return render_template('change-password.html',
                                   question=question,
                                   error='Неверный пароль')

        if not check_password_hash(user_data[1], answer.lower().strip()):
            return render_template('change-password.html',
                                   question=question,
                                   error='Неверный ответ')

        hashed_pw = generate_password_hash(new_pw)
        db.execute('''
            UPDATE users SET password = ? WHERE id = ?
        ''', (hashed_pw, session['user']['id']))
        db.commit()
        return redirect(url_for('index', message='Пароль изменен'))

    return render_template('change-password.html', question=question)

# Маршрут присоединения к комнате (join_room)
@app.route('/join', methods=['POST'])
def join_room():
    if 'user' not in session:
        return redirect(url_for('login'))

    code = request.form['code'].strip().upper()
    db = get_db()

    try:
        # Проверяем статус комнаты только для новых участников
        room = db.execute('''
            SELECT id, is_closed 
            FROM rooms 
            WHERE code = ?
        ''', (code,)).fetchone()

        if not room:
            return render_template('index.html',
                                 user=session.get('user'),
                                 error='Комната не найдена')

        # Проверка только для новых участников
        if room[1]:  # Если комната закрыта
            return render_template('index.html',
                                 user=session.get('user'),
                                 error='Комната закрыта для новых участников')

        # Проверяем, не состоит ли уже пользователь в комнате
        existing = db.execute('''
            SELECT 1 
            FROM participants 
            WHERE user_id = ? AND room_id = ?
        ''', (session['user']['id'], room[0])).fetchone()

        if existing:
            return redirect(url_for('view_room', code=code))

        # Добавляем в участники
        db.execute('''
            INSERT INTO participants (user_id, room_id)
            VALUES (?, ?)
        ''', (session['user']['id'], room[0]))
        db.commit()

        return redirect(url_for('view_room', code=code))

    except sqlite3.IntegrityError:
        return render_template('index.html',
                             user=session.get('user'),
                             error='Ошибка присоединения')
    finally:
        db.close()

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Проверка существования пользователя
        if username in ADMINS:
            # Проверка пароля
            if password == ADMINS[username]:
                session['is_admin'] = True
                return redirect(url_for('admin_panel'))

        return render_template('admin_login.html', error='Неверные данные')
    return render_template('admin_login.html')


@app.route('/admin')
def admin_panel():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    rooms = db.execute('''
        SELECT r.code, r.is_closed, GROUP_CONCAT(u.username, ', ')
        FROM rooms r
        LEFT JOIN participants p ON r.id = p.room_id
        LEFT JOIN users u ON p.user_id = u.id
        GROUP BY r.id
    ''').fetchall()

    return render_template('admin_panel.html', rooms=rooms)


@app.route('/admin/create-room', methods=['POST'])
def create_room():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    code = request.form['code'].strip().upper()
    db = get_db()
    try:
        db.execute('INSERT INTO rooms (code) VALUES (?)', (code,))
        db.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        db.close()

    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle-room/<code>')
def toggle_room(code):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    db.execute('''
        UPDATE rooms 
        SET is_closed = NOT is_closed 
        WHERE code = ?
    ''', (code,))
    db.commit()
    db.close()

    return redirect(url_for('admin_panel'))

@app.route('/leave-room/<code>', methods=['POST'])
def leave_room(code):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        room = db.execute('''
            SELECT id, is_closed 
            FROM rooms 
            WHERE code = ?
        ''', (code,)).fetchone()

        if not room:
            return redirect(url_for('index'))

        # Если комната закрыта, показываем участников
        if room[1]:
            participants = get_participants(room[0])  # Используем функцию
            return render_template('room.html',
                                code=code,
                                error='Выход из закрытой комнаты запрещён',
                                is_closed=True,
                                participants=participants,
                                user=session.get('user'))

        # Удаляем участника из комнаты
        db.execute('''
            DELETE FROM participants 
            WHERE user_id = ? AND room_id = ?
        ''', (session['user']['id'], room[0]))
        db.commit()
        return redirect(url_for('index'))

    finally:
        db.close()


@app.route('/admin/create-assignment/<room_code>', methods=['GET', 'POST'])
def create_assignment(room_code):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        room_id = db.execute('SELECT id FROM rooms WHERE code = ?', (room_code,)).fetchone()[0]

        db.execute('''
            INSERT INTO assignments (room_id, title, description)
            VALUES (?, ?, ?)
        ''', (room_id, title, description))
        db.commit()
        return redirect(url_for('admin_panel'))

    return render_template('create_assignment.html', room_code=room_code)


@app.route('/submit-assignment/<int:assignment_id>', methods=['GET', 'POST'])
def submit_assignment(assignment_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{datetime.now().timestamp()}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            user_id = session['user']['id']
            db.execute('''
                            INSERT INTO submissions (user_id, assignment_id, filename)
                            VALUES (?, ?, ?)
                        ''', (user_id, assignment_id, filename))
            db.commit()

            return redirect(url_for('view_room', code=request.args.get('room_code')))

        assignment = db.execute('SELECT * FROM assignments WHERE id = ?', (assignment_id,)).fetchone()
        return render_template('submit_assignment.html', assignment=assignment)

@app.route('/admin/grade-submission/<int:submission_id>', methods=['GET', 'POST'])
def grade_submission(submission_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    if request.method == 'POST':
        grade = request.form['grade']
        comment = request.form['comment']

        db.execute('''
                    UPDATE submissions 
                    SET grade = ?, comment = ?
                    WHERE id = ?
                ''', (grade, comment, submission_id))
        db.commit()
        return redirect(url_for('admin_panel'))

    submission = db.execute('''
                SELECT s.*, u.username, a.title 
                FROM submissions s
                JOIN users u ON s.user_id = u.id
                JOIN assignments a ON s.assignment_id = a.id
                WHERE s.id = ?
            ''', (submission_id,)).fetchone()

    return render_template('grade_submission.html', submission=submission)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'doc', 'docx', 'odt'}

# Обновленный маршрут просмотра комнаты
@app.route('/room/<code>')
def view_room(code):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        room = db.execute('SELECT id FROM rooms WHERE code = ?', (code,)).fetchone()
        if not room:
            return redirect(url_for('index'))

        assignments = db.execute('''
                    SELECT * FROM assignments WHERE room_id = ?
                ''', (room[0],)).fetchall()

        submissions = db.execute('''
                    SELECT a.title, s.grade, s.comment 
                    FROM submissions s
                    JOIN assignments a ON s.assignment_id = a.id
                    WHERE s.user_id = ?
                ''', (session['user']['id'],)).fetchall()

        return render_template('room.html',
                               code=code,
                               assignments=assignments,
                               submissions=submissions)
    finally:
        db.close()

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
