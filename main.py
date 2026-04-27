import json
from flask import Flask, render_template, request, redirect, jsonify, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import uuid
import subprocess
import tempfile

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
        # get exams created by user
        c.execute('SELECT * FROM exams WHERE au = ?', (session['email'],))
        exams = c.fetchall()
        conn.close()
        exam_lengths = []
        for exam in exams:
            exam_ql = json.loads(exam[4])
            exam_lengths.append(len(exam_ql))
        return render_template('dashboard.html', name=name, user_data=user_data, exams=exams, exam_lengths=exam_lengths)
    
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
    question_id = str(uuid.uuid4())
    c.execute('INSERT INTO problems (id, title, au, sub, con, q, ao) VALUES (?, ?, ?, ?, ?, ?, ?)', (question_id, 'New Question', session['email'], 'custom', 'This is a placeholder question. Replace it with your own content.', 'What is the answer to this question?', json.dumps(['Option A', 'Option B', 'Option C', 'Option D'])))
    c.execute('INSERT INTO exams (id, title, date, au, ql) VALUES (?, ?, ?, ?, ?)', (exam_id, 'New Exam', '2024-01-01', session['email'], json.dumps([question_id])))
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
        question_id_list = json.loads(ql_data[0]) if ql_data else []
        question_list = []
        for question_id in question_id_list:
            c.execute('SELECT * FROM problems WHERE id = ?', (question_id,))
            question_data = c.fetchone()
            if question_data:
                question_list.append(question_data)
        conn.close()
        return render_template('edit.html', exam_data=exam_data, question_list=question_list)
    elif action == 'delete':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('DELETE FROM exams WHERE id = ?', (exam_id,))
        conn.commit()
        conn.close()
        return redirect('/')
    elif action == 'update_exam_parameters':
        data = request.get_json()
        exam_id = data['exam_id']
        parameter = data['parameter']
        new_value = data['value']
        if parameter in ['title']:
            conn = sqlite3.connect('db.sqlite3')
            c = conn.cursor()
            c.execute(f'UPDATE exams SET {parameter} = ? WHERE id = ?', (new_value, exam_id))
            conn.commit()
            conn.close()
            return jsonify({'status': 'success'})
    elif action == 'add_question':
        # problems (id TEXT, title TEXT, au TEXT, sub TEXT, con TEXT, q TEXT, ao TEXT)
        question_id = str(uuid.uuid4())
        title = request.form['title'] if 'title' in request.form else 'New Question'
        sub = 'custom'
        con = request.form['stimulus'] if 'stimulus' in request.form else ''
        q = request.form['question'] if 'question' in request.form else ''
        ao1 = request.form['ao1'] if 'ao1' in request.form else ''
        ao2 = request.form['ao2'] if 'ao2' in request.form else ''
        ao3 = request.form['ao3'] if 'ao3' in request.form else ''
        ao4 = request.form['ao4'] if 'ao4' in request.form else ''
        ao_list = [ao1, ao2, ao3, ao4]
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('INSERT INTO problems (id, title, au, sub, con, q, ao) VALUES (?, ?, ?, ?, ?, ?, ?)', (question_id, title, session['email'], sub, con, q, json.dumps(ao_list)))
        conn.commit()
        c.execute('SELECT ql FROM exams WHERE id = ?', (exam_id,))
        ql_data = c.fetchone()
        question_list = json.loads(ql_data[0]) if ql_data else []
        question_list.append(question_id)
        c.execute('UPDATE exams SET ql = ? WHERE id = ?', (json.dumps(question_list), exam_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'question_id': question_id})
    elif action == 'get_question_list':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT ql FROM exams WHERE id = ?', (exam_id,))
        ql_data = c.fetchone()
        question_id_list = json.loads(ql_data[0]) if ql_data else []
        question_list = []
        for question_id in question_id_list:
            c.execute('SELECT * FROM problems WHERE id = ?', (question_id,))
            question_data = c.fetchone()
            if question_data:
                question_list.append({
                    'id': question_data[0],
                    'title': question_data[1],
                    'au': question_data[2],
                    'sub': question_data[3],
                    'con': question_data[4] or '',
                    'q': question_data[5] or '',
                    'ao': json.loads(question_data[6]) if question_data[6] else []
                })
        conn.close()
        return jsonify({'status': 'success', 'question_list': question_list})
    elif action == 'export':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()

        c.execute('SELECT * FROM exams WHERE id = ?', (exam_id,))
        exam_data = c.fetchone()
        if not exam_data:
            conn.close()
            return "Exam not found", 404

        exam_dict = {
            'id': exam_data[0],
            'title': exam_data[1],
            'date': exam_data[2],
            'au': exam_data[3],
            'ql': json.loads(exam_data[4])
        }

        questions = []
        for question_id in exam_dict['ql']:
            c.execute('SELECT * FROM problems WHERE id = ?', (question_id,))
            question_data = c.fetchone()
            if question_data:
                questions.append({
                    'id': question_data[0],
                    'title': question_data[1],
                    'au': question_data[2],
                    'sub': question_data[3],
                    'con': question_data[4] or '',
                    'q': question_data[5] or '',
                    'ao': json.loads(question_data[6]) if question_data[6] else []
                })

        conn.close()

        tex_string = render_template('exam.tex', exam=exam_dict, questions=questions)

        with tempfile.TemporaryDirectory() as tmpdir:
            tex_path = os.path.join(tmpdir, 'exam.tex')
            pdf_path = os.path.join(tmpdir, 'exam.pdf')

            with open(tex_path, 'w', encoding='utf-8') as f:
                f.write(tex_string)

            try:
                subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', 'exam.tex'],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    text=True
                )
            except subprocess.CalledProcessError as e:
                return (
                    "LaTeX compilation failed.\n\nSTDOUT:\n"
                    + e.stdout
                    + "\n\nSTDERR:\n"
                    + e.stderr,
                    500,
                    {'Content-Type': 'text/plain; charset=utf-8'}
                )

            return send_file(
                pdf_path,
                as_attachment=True,
                download_name=f"{exam_dict['title']}.pdf"
            )
    else:
        return "Invalid action", 400
    
@login_required
@app.route('/question/<string:question_id>/<string:action>', methods=['POST'])
def question_action(question_id, action):
    if action == 'update_parameters':
        data = request.get_json()
        parameter = data['parameter']
        new_value = data['value']
        if parameter in ['title', 'con', 'q']:
            conn = sqlite3.connect('db.sqlite3')
            c = conn.cursor()
            c.execute(f'UPDATE problems SET {parameter} = ? WHERE id = ?', (new_value, question_id))
            conn.commit()
            conn.close()
        if parameter in ['ao1', 'ao2', 'ao3', 'ao4']:
            conn = sqlite3.connect('db.sqlite3')
            c = conn.cursor()
            c.execute('SELECT ao FROM problems WHERE id = ?', (question_id,))
            ao_data = c.fetchone()
            ao_list = json.loads(ao_data[0]) if ao_data else ['', '', '', '']
            index = int(parameter[2]) - 1
            ao_list[index] = new_value
            c.execute('UPDATE problems SET ao = ? WHERE id = ?', (json.dumps(ao_list), question_id))
            conn.commit()
            conn.close()
        return jsonify({'status': 'success'})
    elif action == 'delete':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('DELETE FROM problems WHERE id = ?', (question_id,))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})  
    elif action == 'get_content':
        conn = sqlite3.connect('db.sqlite3')
        c = conn.cursor()
        c.execute('SELECT * FROM problems WHERE id = ?', (question_id,))
        question_data = c.fetchone()
        conn.close()
        if question_data:
            return jsonify({
                'status': 'success',
                'question': {
                    'id': question_data[0],
                    'title': question_data[1],
                    'au': question_data[2],
                    'sub': question_data[3],
                    'con': question_data[4],
                    'q': question_data[5],
                    'ao': json.loads(question_data[6])
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Question not found'}), 404
if __name__ == '__main__':
    app.run(debug=True)