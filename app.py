
from flask import Flask, render_template, request, session, redirect, url_for
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import random
from datetime import datetime, timedelta

# MySQL Configuration
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = 'Chandana@2004'
MYSQL_DB = 'secure_login'
SECRET_KEY = 'mysecretkey'

app = Flask(__name__)
app.secret_key = SECRET_KEY

# MySQL setup
app.config['MYSQL_HOST'] = MYSQL_HOST
app.config['MYSQL_USER'] = MYSQL_USER
app.config['MYSQL_PASSWORD'] = MYSQL_PASSWORD
app.config['MYSQL_DB'] = MYSQL_DB

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'

# Add your Gmail here
app.config['MAIL_USERNAME'] = 'chandanakonan2004@gmail.com'
app.config['MAIL_PASSWORD'] = 'abcd efgh ijkl mnop'


# Initialize extensions
mysql = MySQL(app)
bcrypt = Bcrypt(app)
mail = Mail(app)



# Home page
@app.route('/')
def home():
    return render_template('home.html')


# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()

        # check existing user
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return redirect(url_for('login'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (email, hashed_password)
        )
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html')



# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            failed_attempts = int(user[5]) if user[5] else 0
            lock_until = user[6]


            if lock_until:
                try:
                    lock_until = lock_until if isinstance(lock_until, datetime) else datetime.fromisoformat(str(lock_until))
                except:
                    lock_until = None

            # Check if account is locked
            if lock_until and datetime.now() < lock_until:
                cursor.close()
                return "Account locked. Try again later."

            # Check password
            if bcrypt.check_password_hash(user[2], password):
                # Reset failed attempts on success
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE email = %s",
                    (email,)
                )
                mysql.connection.commit()

                otp = str(random.randint(100000, 999999))
                print("OTP sent to terminal:", otp)

                cursor.execute(
                    "UPDATE users SET otp = %s WHERE email = %s",
                    (otp, email)
                )
                mysql.connection.commit()

                session['email'] = email
                cursor.close()

                return render_template('otp_verify.html')

            else:
                failed_attempts += 1

                if failed_attempts >= 3:
                    lock_time = datetime.now() + timedelta(minutes=5)

                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s, lock_until = %s WHERE email = %s",
                        (failed_attempts, lock_time, email)
                    )
                    mysql.connection.commit()
                    cursor.close()

                    return "Too many failed attempts. Account locked for 5 minutes."

                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = %s WHERE email = %s",
                        (failed_attempts, email)
                    )
                    mysql.connection.commit()
                    cursor.close()

                    return f"Invalid password. Attempts left: {3 - failed_attempts}"

        cursor.close()
        return "Email not found"

    return render_template('login.html')


# otp verify
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    entered_otp = request.form['otp']
    email = session.get('email')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT otp FROM users WHERE email = %s", (email,))
    stored_otp = cursor.fetchone()
    cursor.close()

    if stored_otp and entered_otp == stored_otp[0]:
        return redirect(url_for('dashboard'))
    else:
        return "Invalid OTP"
    

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')
    

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# frogot password 
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            otp = str(random.randint(100000, 999999))
            print("Reset OTP:", otp)

            cursor.execute(
                "UPDATE users SET reset_otp = %s WHERE email = %s",
                (otp, email)
            )
            mysql.connection.commit()
            session['reset_email'] = email

            cursor.close()
            return render_template('reset_password.html')

        cursor.close()
        return "Email not found"

    return render_template('forgot_password.html')


#reset password 
@app.route('/reset_password', methods=['POST'])
def reset_password():
    otp = request.form['otp']
    new_password = request.form['new_password']
    email = session.get('reset_email')

    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT reset_otp FROM users WHERE email = %s",
        (email,)
    )
    stored_otp = cursor.fetchone()

    if stored_otp and otp == stored_otp[0]:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        cursor.execute(
            "UPDATE users SET password = %s WHERE email = %s",
            (hashed_password, email)
        )
        mysql.connection.commit()
        cursor.close()

        return "Password Reset Successfully"

    cursor.close()
    return "Invalid OTP"



if __name__ == '__main__':
    app.run(debug=True)