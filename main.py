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

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


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

        for code in ['ROOM1', 'ROOM2', 'ROOM3']:
            cursor.execute('INSERT OR IGNORE INTO rooms (code) VALUES (?)', (code,))

        db.commit()
        cursor.close()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

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

# Основные маршруты
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
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user[3], password):
            session['user'] = {
                'id': user[0],
                'username': user[1],
                'email': user[2]
            }
            return redirect(url_for('index'))
        return render_template('login.html', error='Неверные данные')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))


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
            db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, user[0]))
            db.commit()
            return render_template('login.html', success='Пароль изменен')

        return render_template('forgot-password.html', error='Ошибка проверки')

    return render_template('forgot-password.html')


@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    question = db.execute('SELECT security_question FROM users WHERE id = ?', (session['user']['id'],)).fetchone()[0]

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
        db.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, session['user']['id']))
        db.commit()
        return redirect(url_for('index'))

    return render_template('change-password.html', question=question)


@app.route('/join', methods=['POST'])
def join_room():
    if 'user' not in session:
        return redirect(url_for('login'))

    code = request.form['code'].strip().upper()
    db = get_db()

    try:
        room = db.execute('SELECT id FROM rooms WHERE code = ?', (code,)).fetchone()
        if not room:
            return render_template('index.html', error='Комната не найдена')

        try:
            db.execute('INSERT INTO participants (user_id, room_id) VALUES (?, ?)',
                       (session['user']['id'], room[0]))
            db.commit()
        except sqlite3.IntegrityError:
            pass

        return redirect(url_for('view_room', code=code))
    finally:
        db.close()

@app.route('/leave-room/<code>', methods=['POST'])
def leave_room(code):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        # Получаем ID комнаты
        room = db.execute('SELECT id FROM rooms WHERE code = ?', (code,)).fetchone()
        if not room:
            return redirect(url_for('index'))

        # Удаляем участника
        db.execute('''
            DELETE FROM participants 
            WHERE user_id = ? AND room_id = ?
        ''', (session['user']['id'], room[0]))
        db.commit()

        return redirect(url_for('index'))
    except Exception as e:
        db.rollback()
        return render_template('room.html',
                            code=code,
                            error='Ошибка выхода из комнаты')
    finally:
        db.close()

@app.route('/room/<code>')
def view_room(code):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()
    try:
        # Получаем информацию о комнате
        room = db.execute('SELECT id FROM rooms WHERE code = ?', (code,)).fetchone()
        if not room:
            return redirect(url_for('index'))

        # Получаем задания для комнаты
        assignments = db.execute('''
            SELECT * FROM assignments 
            WHERE room_id = ?
        ''', (room[0],)).fetchall()

        # Получаем список участников
        participants = db.execute('''
            SELECT u.username 
            FROM participants p
            JOIN users u ON p.user_id = u.id
            WHERE p.room_id = ?
        ''', (room[0],)).fetchall()

        return render_template('room.html',
                            code=code,
                            assignments=assignments,
                            participants=[p[0] for p in participants])
    finally:
        db.close()


# Админские маршруты
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
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
        SELECT 
            r.code, 
            COALESCE(GROUP_CONCAT(u.username, ', '), 'Нет участников') as participants
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


@app.route('/admin/room/<code>/assignments')
def room_assignments(code):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    try:
        assignments = db.execute('''
            SELECT * FROM assignments 
            WHERE room_id = (SELECT id FROM rooms WHERE code = ?)
        ''', (code,)).fetchall()

        return render_template('room_assignments.html',
                               code=code,
                               assignments=assignments)
    finally:
        db.close()

@app.route('/admin/grade-submission/<int:submission_id>', methods=['GET', 'POST'])
def grade_submission(submission_id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    if request.method == 'POST':
        grade = request.form['grade']
        comment = request.form['comment']

        db.execute('UPDATE submissions SET grade = ?, comment = ? WHERE id = ?',
                   (grade, comment, submission_id))
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

@app.route('/admin/room/<code>/submissions')
def room_submissions(code):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    db = get_db()
    try:
        # Получаем все отправленные работы для комнаты
        submissions = db.execute('''
            SELECT 
                s.id,
                u.username,
                a.title,
                s.filename,
                s.grade,
                s.comment,
                s.submitted_at
            FROM submissions s
            JOIN assignments a ON s.assignment_id = a.id
            JOIN users u ON s.user_id = u.id
            WHERE a.room_id = (
                SELECT id FROM rooms WHERE code = ?
            )
            ORDER BY s.submitted_at DESC
        ''', (code,)).fetchall()

        return render_template('room_submissions.html',
                            code=code,
                            submissions=submissions)
    finally:
        db.close()

@app.route('/uploads/<filename>')
def download_submission(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'doc', 'docx', 'odt'}


if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
