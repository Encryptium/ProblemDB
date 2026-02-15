import json
from flask import Flask, render_template, request, redirect, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import uuid

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SECRET_KEY'] = "uuid.uuid4().hex"

# make login required decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            return redirect('/signin')
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    if 'email' in session:
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT name FROM accounts WHERE email = ?', (session['email'],))
        name = c.fetchone()[0]
        c.execute('SELECT * FROM accounts WHERE email = ?', (session['email'],))
        user_data = c.fetchone()
        conn.close()
        return render_template('dashboard.html', name=name, user_data=user_data)
    
    return render_template('index.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT pwd FROM accounts WHERE email = ?', (email,))
        pwd = c.fetchone()
        conn.close()

        if pwd and check_password_hash(pwd[0], password):
            session['email'] = email
        
        return redirect('/')
    return render_template('signin.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        password_confirmation = request.form['confirm_password']

        if password != password_confirmation:
            return render_template('signup.html', error="Passwords do not match.")
        
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('INSERT INTO accounts (email, name, pwd) VALUES (?, ?, ?)', (email, name, hashed_password))
        conn.commit()
        conn.close()

        session['email'] = email
        return redirect('/')
    
    return render_template('signup.html')

@app.route('/signout')
def signout():
    session.pop('email', None)
    return redirect('/')

@login_required
@app.route('/exam/create')
def create_exam():
    exam_id = str(uuid.uuid4())
    conn = sqlite3.connect('db.sqlite3')
    c = conn.cursor()
    c.execute('INSERT INTO exams (id, title, date, ql) VALUES (?, ?, ?, ?)', (exam_id, 'New Exam', '2024-01-01', '[]'))
    conn.commit()
    conn.close()
    return redirect('/exam/' + exam_id + '/edit')

@login_required
@app.route('/exam/<string:exam_id>/<string:action>', methods=['GET', 'POST'])
def exam_action(exam_id, action):
    if action == 'preview':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT * FROM exams WHERE id = ?', (exam_id,))
        exam_data = c.fetchone()
        conn.close()

        return render_template('preview.html', exam_data=exam_data)
    elif action == 'edit':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        if request.method == 'POST':
            new_name = request.form['name']
            new_date = request.form['date']
            question_list = request.form['ql']
            c.execute('UPDATE exams SET title = ?, date = ?, ql = ? WHERE id = ?', (new_name, new_date, question_list, exam_id))
            conn.commit()
            conn.close()
            return redirect('/')
        
        c.execute('SELECT * FROM exams WHERE id = ?', (exam_id,))
        exam_data = c.fetchone()
        c.execute('SELECT ql FROM exams WHERE id = ?', (exam_id,))
        ql_data = c.fetchone()
        question_list = json.loads(ql_data[0]) if ql_data else []
        conn.close()
        return render_template('edit.html', exam_data=exam_data, question_list=question_list)
    elif action == 'delete':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('DELETE FROM exams WHERE id = ?', (exam_id,))
        conn.commit()
        conn.close()
        return redirect('/')
    else:
        return "Invalid action", 400

if __name__ == '__main__':
    app.run(debug=True)