from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from bson.objectid import ObjectId
import os
import secrets

app = Flask(__name__, template_folder='../templates')

# Generate a secret key if not exists
def get_or_create_secret_key():
    try:
        return os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    except:
        return secrets.token_hex(32)

app.secret_key = get_or_create_secret_key()
app.config["MONGO_URI"] = os.environ.get('MONGODB_URI')
mongo = PyMongo(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.role = user_data.get('role', 'user')
        self.approved = user_data.get('approved', False)

    @staticmethod
    def get(user_id):
        user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def index():
    if not current_user.approved:
        flash('Your account is pending approval.', 'warning')
        return redirect(url_for('pending'))
    return render_template('calculator.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        if mongo.db.users.find_one({'email': email}):
            flash('Email already registered', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        user_data = {
            'email': email,
            'password': hashed_password,
            'name': name,
            'role': 'user',
            'approved': False
        }
        
        # Make first user an admin
        if mongo.db.users.count_documents({}) == 0:
            user_data['role'] = 'admin'
            user_data['approved'] = True

        mongo.db.users.insert_one(user_data)
        flash('Registration successful! Please wait for admin approval.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = mongo.db.users.find_one({'email': email})
        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            if not user.approved:
                flash('Your account is pending approval.', 'warning')
                return redirect(url_for('pending'))
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/pending')
def pending():
    return render_template('pending.html')

@app.route('/admin')
@login_required
@admin_required
def admin():
    users = mongo.db.users.find({'role': 'user'})
    return render_template('admin.html', users=users)

@app.route('/admin/approve/<user_id>')
@login_required
@admin_required
def approve_user(user_id):
    mongo.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'approved': True}}
    )
    flash('User approved successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete/<user_id>')
@login_required
@admin_required
def delete_user(user_id):
    mongo.db.users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))