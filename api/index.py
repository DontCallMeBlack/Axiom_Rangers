from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from bson.objectid import ObjectId
import os
import secrets
import traceback

app = Flask(__name__, template_folder='../templates')

# Error handler for 500 errors
@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "details": str(error)}), 500

# Error handler for 404 errors
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not Found", "details": str(error)}), 404

# MongoDB client as a global variable
client = None

def get_db():
    try:
        global client
        mongo_uri = os.environ.get('MONGODB_URI')
        if not mongo_uri:
            mongo_uri = "mongodb+srv://celticheroesdcmb:Suppmain123@cluster0.ognfnvj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
            os.environ['MONGODB_URI'] = mongo_uri
            print("Using default MongoDB URI")
            
        if client is None:
            print(f"Attempting to connect to MongoDB...")
            # Parse the URI to get the database name
            from urllib.parse import urlparse
            uri_parts = urlparse(mongo_uri)
            db_name = uri_parts.path.strip('/') or 'damage_ranger'
            
            client = MongoClient(mongo_uri, 
                               serverSelectionTimeoutMS=10000,  # Increased timeout
                               connectTimeoutMS=10000,
                               socketTimeoutMS=10000,
                               retryWrites=True)
            # Test the connection explicitly
            client.admin.command('ping')
            print("Successfully connected to MongoDB")
        return client.get_default_database()
    except Exception as e:
        print(f"MongoDB Connection Error: {str(e)}")
        print(f"Connection String: {mongo_uri if mongo_uri else 'Not set'}")
        traceback.print_exc()
        return None

@app.before_request
def before_request():
    try:
        g.db = get_db()
        if g.db is None:
            print("Database connection returned None")
            return jsonify({
                "error": "Database connection failed",
                "message": "Could not connect to MongoDB. Please check your connection string and network settings."
            }), 500
            
        # Verify we can actually perform operations
        g.db.command('ping')
    except Exception as e:
        print(f"Before request error: {str(e)}")
        traceback.print_exc()
        return jsonify({
            "error": "Database connection failed",
            "message": f"MongoDB Error: {str(e)}"
        }), 500

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None:
        global client
        if client is not None:
            client.close()
            client = None

# Generate a secret key if not exists
def get_or_create_secret_key():
    try:
        return os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    except:
        return secrets.token_hex(32)

app.secret_key = get_or_create_secret_key()
# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Basic route to test the application
@app.route('/api/health')
def health_check():
    try:
        # Test database connection
        g.db.command('ping')
        return jsonify({"status": "healthy", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.role = user_data.get('role', 'user')
        self.approved = user_data.get('approved', False)

    @staticmethod
    def get(user_id):
        user_data = g.db.users.find_one({'_id': ObjectId(user_id)})
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
def index():
    try:
        if g.db.command('ping'):
            return jsonify({
                "status": "ok",
                "message": "Application is running",
                "database": "connected"
            })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
            "database": "disconnected"
        }), 500

@app.route('/calculator')
@login_required
def calculator():
    if not current_user.approved:
        flash('Your account is pending approval.', 'warning')
        return redirect(url_for('pending'))
    return render_template('calculator.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            data = request.form
            if not data:
                data = request.get_json()  # Try to get JSON data if form data is not present
            
            email = data.get('email')
            password = data.get('password')
            name = data.get('name')

            if not all([email, password, name]):
                return jsonify({
                    'error': 'Missing required fields',
                    'message': 'Email, password, and name are required'
                }), 400

            # Check if user exists
            existing_user = g.db.users.find_one({'email': email})
            if existing_user:
                return jsonify({
                    'error': 'User exists',
                    'message': 'Email already registered'
                }), 409

            # Create user data
            hashed_password = generate_password_hash(password)
            user_data = {
                'email': email,
                'password': hashed_password,
                'name': name,
                'role': 'user',
                'approved': False
            }

            # Make first user an admin
            try:
                user_count = g.db.users.count_documents({})
                if user_count == 0:
                    user_data['role'] = 'admin'
                    user_data['approved'] = True
            except Exception as e:
                print(f"Error checking user count: {str(e)}")
                user_data['role'] = 'admin'  # Default to admin if can't check count
                user_data['approved'] = True

            # Insert the new user
            result = g.db.users.insert_one(user_data)
            
            if result.inserted_id:
                response_data = {
                    'success': True,
                    'message': 'Registration successful',
                    'role': user_data['role'],
                    'approved': user_data['approved']
                }
                return jsonify(response_data), 200
            else:
                return jsonify({
                    'error': 'Database error',
                    'message': 'Failed to create user'
                }), 500

        except Exception as e:
            print(f"Signup error: {str(e)}")
            traceback.print_exc()
            return jsonify({
                'error': 'Server error',
                'message': str(e)
            }), 500

    # GET request - return the signup form
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = g.db.users.find_one({'email': email})
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
    users = list(g.db.users.find({'role': 'user'}))
    return render_template('admin.html', users=users)

@app.route('/admin/approve/<user_id>')
@login_required
@admin_required
def approve_user(user_id):
    g.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'approved': True}}
    )
    flash('User approved successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete/<user_id>')
@login_required
@admin_required
def delete_user(user_id):
    g.db.users.delete_one({'_id': ObjectId(user_id)})
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))