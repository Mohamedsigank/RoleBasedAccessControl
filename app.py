from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'ThisIsNotASecret:p'
app.config['SQLALCHEMY_ECHO'] = True  # Enable SQL query logging for debugging

db = SQLAlchemy(app)


# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), default='User')  # Roles: Admin, User, Moderator

    def __init__(self, username, password, role='User'):
        self.username = username
        self.password = generate_password_hash(password)  # Hash the password
        self.role = role


# Role-Based Access Decorators
def role_required(allowed_roles):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if 'logged_in' in session:
                user_role = session.get('role')
                if user_role in allowed_roles:
                    return func(*args, **kwargs)
            return redirect(url_for('index'))
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator


# Routes
@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html', message="Welcome to the RBAC System!")


@app.route('/register/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'User')  # Default role is 'User'

        try:
            # Create new user and add to database
            new_user = User(username=username, password=password, role=role)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return render_template('register.html', message="Username already exists. Try another.")
    return render_template('register.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        print(f"Attempting login for username: {username}")

        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User found: {user.username}, role: {user.role}")
            if check_password_hash(user.password, password):
                print("Password check passed.")
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user.role
                return redirect(url_for('dashboard'))
            else:
                print("Password check failed.")
                return render_template('login.html', message="Invalid password.")
        else:
            print("User not found.")
            return render_template('login.html', message="Invalid username or password.")
    return render_template('login.html')


@app.route('/logout/')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard/')
@role_required(['Admin', 'Moderator', 'User'])
def dashboard():
    return render_template('home.html', username=session.get('username'), role=session.get('role'))


@app.route('/admin/')
@role_required(['Admin'])
def admin_dashboard():
    return render_template('admin_dashboard.html')


@app.route('/moderator/')
@role_required(['Admin', 'Moderator'])
def moderator_dashboard():
    return render_template('moderator_dashboard.html')


# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database and tables are created
    app.run(debug=True)
