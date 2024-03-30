from flask import Flask, request, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            name TEXT,
            email TEXT,
            password TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS friend_requests (
            requestor TEXT,
            acceptor TEXT,
            status INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def hash_pair(str1, str2):
    hash1 = hashlib.sha256(str1.encode()).digest()
    hash2 = hashlib.sha256(str2.encode()).digest()
    combined_hash = bytes(a ^ b for a, b in zip(hash1, hash2))
    hashed = hashlib.sha256(combined_hash).hexdigest()
    return hashed

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone() is not None:
            conn.close()
            return "Error: Email already exists"

        c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT name, password FROM users WHERE email = ?', (email,))
        result = c.fetchone()

        if result is None:
            return 'User not found'
        else:
            name, hashed_password = result
            if check_password_hash(hashed_password, password):
                session['name'] = name
                session['email'] = email
                email_hash = 'f_' + hashlib.sha256(email.encode()).hexdigest()
                c.execute(f'''
                    CREATE TABLE IF NOT EXISTS {email_hash} (
                        name TEXT,
                        email TEXT,
                        amount INTEGER
                    )
                ''')
                conn.commit()
                return redirect(url_for('home'))
            else:
                return 'Incorrect password'
    else:
        return render_template('login.html')
    
@app.route('/add_friend', methods=['GET', 'POST'])
def add_friend():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        friend_email = request.form['email']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Check if friend_email exists in users table
        c.execute('SELECT * FROM users WHERE email = ?', (friend_email,))
        if c.fetchone() is None:
            conn.close()
            return "Error: Your friend doesn't use our app. Refer our app to your friend."

        # Check if friend request already exists
        c.execute('SELECT * FROM friend_requests WHERE requestor = ? AND acceptor = ? AND status = 0', (session['email'], friend_email))
        if c.fetchone() is not None:
            conn.close()
            return "Error: Friend request already sent"

        # Check if friend_email already exists in 'f_'+hash(session email) table
        email_hash = 'f_' + hashlib.sha256(session['email'].encode()).hexdigest()
        c.execute(f'SELECT * FROM "{email_hash}" WHERE email = ?', (friend_email,))
        if c.fetchone() is not None:
            conn.close()
            return "Error: Already a friend"

        c.execute('INSERT INTO friend_requests (requestor, acceptor, status) VALUES (?, ?, 0)', (session['email'], friend_email))
        conn.commit()
        conn.close()

        return 'Friend request sent'
    else:
        return render_template('request.html')
    
@app.route('/show_requests', methods=['GET', 'POST'])
def show_requests():
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        friend_email = request.form['email']
        action = int(request.form['action'])

        c.execute('UPDATE friend_requests SET status = ? WHERE requestor = ? AND acceptor = ?', (action, friend_email, session['email']))

        if action == 1:
            friend_name = request.form['name']
            email_hash = 'f_' + hashlib.sha256(session['email'].encode()).hexdigest()
            c.execute(f'INSERT INTO "{email_hash}" (name, email, amount) VALUES (?, ?, 0)', (friend_name, friend_email))

            email_hash = 'f_' + hashlib.sha256(friend_email.encode()).hexdigest()
            c.execute(f'INSERT INTO "{email_hash}" (name, email, amount) VALUES (?, ?, 0)', (session['name'], session['email']))

            xor_hash = hash_pair(session['email'], friend_email)
            session_email_field = session['email'].replace('@', '_').replace('.', '_')
            friend_email_field = friend_email.replace('@', '_').replace('.', '_')
            c.execute(f'''
                CREATE TABLE IF NOT EXISTS "l_{xor_hash}" (
                date TEXT,
                purpose TEXT,
                amount INTEGER,
                "{session_email_field}" INTEGER,
                "{friend_email_field}" INTEGER
                )
            ''')

        conn.commit()

    c.execute('SELECT acceptor FROM friend_requests WHERE requestor = ? AND status = 0', (session['email'],))
    acceptors = c.fetchall()

    sent_requests = []
    for acceptor in acceptors:
        c.execute('SELECT name FROM users WHERE email = ?', acceptor)
        result = c.fetchone()
        if result is not None:
            sent_requests.append((acceptor[0], result[0]))

    c.execute('SELECT requestor FROM friend_requests WHERE acceptor = ? AND status = 0', (session['email'],))
    requestors = c.fetchall()

    received_requests = []
    for requestor in requestors:
        c.execute('SELECT name FROM users WHERE email = ?', requestor)
        result = c.fetchone()
        if result is not None:
            received_requests.append((requestor[0], result[0]))

    conn.close()

    return render_template('pending_req.html', sent_requests=sent_requests, received_requests=received_requests)
    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    email_hash = 'f_' + hashlib.sha256(session['email'].encode()).hexdigest()
    c.execute(f'SELECT name, amount, email FROM "{email_hash}"')
    friends = c.fetchall()

    conn.close()

    return render_template('home.html', name=session['name'], email=session['email'], friends=friends)

@app.route('/ledger/<friend_email>')
def ledger(friend_email):
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    table_name = 'l_' + hash_pair(session['email'], friend_email)
    session_email_field = session['email'].replace('@', '_').replace('.', '_')
    friend_email_field = friend_email.replace('@', '_').replace('.', '_')
    c.execute(f'SELECT date, purpose, amount, "{session_email_field}", "{friend_email_field}" FROM "{table_name}"')
    raw_transactions = c.fetchall()

    email_hash = 'f_' + hashlib.sha256(session['email'].encode()).hexdigest()
    c.execute(f'SELECT amount FROM "{email_hash}" WHERE email = ?', (friend_email,))
    friend_amount = c.fetchone()

    conn.close()

    # Calculate sign for each transaction
    transactions = []
    for transaction in raw_transactions:
        sign = '-' if transaction[3] == 0 and transaction[4] == 1 else '+'
        transactions.append((*transaction, sign))

    transactions.sort(key=lambda x: x[0], reverse=True)

    return render_template('ledger.html', transactions=transactions, friend_amount=friend_amount[0] if friend_amount else 0, friend_email=friend_email)

@app.route('/ledger/<friend_email>/expense', methods=['GET', 'POST'])
def add_expense(friend_email):
    if 'email' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        purpose = request.form['purpose']
        amount = int(request.form['amount'])
        option = request.form['option']

        session_email_field = session['email'].replace('@', '_').replace('.', '_')
        friend_email_field = friend_email.replace('@', '_').replace('.', '_')

        if option == '1' or option == '3':
            amount /= 2

        session_email_value = 1 if option in ['1', '2'] else 0
        friend_email_value = 1 if option in ['3', '4'] else 0

        table_name = 'l_' + hash_pair(session['email'], friend_email)
        c.execute(f'INSERT INTO "{table_name}" (date, purpose, amount, "{session_email_field}", "{friend_email_field}") VALUES (?, ?, ?, ?, ?)', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), purpose, amount, session_email_value, friend_email_value))
        # Code to calculate the new amount
        c.execute(f'SELECT amount, "{session_email_field}", "{friend_email_field}" FROM "{table_name}"')
        transactions = c.fetchall()

        new_amount = 0
        for transaction in transactions:
            amount, session_email_value, friend_email_value = transaction
            sign = '-' if session_email_value == 0 and friend_email_value == 1 else '+'
            new_amount += amount if sign == '+' else -amount

        # Code to update the 'f_+hash(session['email'])' table
        c.execute(f"UPDATE \"f_{hashlib.sha256(session['email'].encode()).hexdigest()}\" SET amount = ? WHERE email = ?", (new_amount, friend_email))

        # Code to update the 'f_+hash(friend_email)' table
        c.execute(f'UPDATE "f_{hashlib.sha256(friend_email.encode()).hexdigest()}" SET amount = ? WHERE email = ?', (-new_amount, session['email']))

        conn.commit()
        return redirect(url_for('ledger', friend_email=friend_email))

    else:
        c.execute('SELECT name FROM users WHERE email = ?', (friend_email,))
        friend_username = c.fetchone()[0]
        return render_template('expense.html', name=session['name'], friend_username=friend_username)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)