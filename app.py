import os
import cloudinary
import cloudinary.uploader
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- App and Extension Initialization ---
app = Flask(__name__)
db = SQLAlchemy()
login_manager = LoginManager()

# --- App Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

# --- Cloudinary Configuration ---
# This connects your app to your Cloudinary account using secrets from Render
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET')
)

# --- Connect Extensions to the App ---
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.Text, nullable=False) # Changed to Text for long Cloudinary URLs
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Main Routes (Web Pages) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            if user.role == 'admin': return redirect(url_for('admin_dashboard'))
            if user.role == 'sub-admin': return redirect(url_for('sub_admin_dashboard'))
            return redirect(url_for('student_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Dashboards ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student': return redirect(url_for('login'))
    if request.method == 'POST':
        if 'image' not in request.files or request.files['image'].filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['image']
        if file:
            # Upload the file to Cloudinary instead of saving locally
            upload_result = cloudinary.uploader.upload(file)
            image_url = upload_result['secure_url']

            new_submission = Submission(
                image_filename=image_url, # Save the full URL from Cloudinary
                description=request.form['description'],
                user_id=current_user.id,
                department=current_user.department
            )
            db.session.add(new_submission)
            db.session.commit()
            flash('Image uploaded successfully! Awaiting review.')
            return redirect(url_for('student_dashboard'))
    return render_template('student.html')

@app.route('/sub_admin_dashboard')
@login_required
def sub_admin_dashboard():
    if current_user.role != 'sub-admin': return redirect(url_for('login'))
    submissions = Submission.query.filter_by(department=current_user.department, status='pending').all()
    return render_template('sub_admin.html', submissions=submissions)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': return redirect(url_for('login'))
    submissions = Submission.query.filter_by(status='approved_by_sub').all()
    return render_template('admin.html', submissions=submissions)

# --- Actions ---
@app.route('/approve/<int:submission_id>')
@login_required
def approve_submission(submission_id):
    if current_user.role != 'sub-admin': return redirect(url_for('login'))
    submission = db.get_or_404(Submission, submission_id)
    if submission.department == current_user.department:
        submission.status = 'approved_by_sub'
        db.session.commit()
        flash('Submission approved and forwarded to main admin.')
    return redirect(url_for('sub_admin_dashboard'))

# --- Custom Command to Set Up the Database ---
@app.cli.command("init-db")
def init_db_command():
    """Creates tables and default users."""
    db.create_all()
    if User.query.filter_by(username='admin').first() is None:
        print("Creating default users...")
        users = [
            User(username='admin', role='admin', department='College'),
            User(username='teacher_cs', role='sub-admin', department='Computer Science'),
            User(username='student_cs', role='student', department='Computer Science')
        ]
        passwords = ['admin123', 'teacher123', 'student123']
        for i, user in enumerate(users):
            user.set_password(passwords[i])
            db.session.add(user)
        db.session.commit()
        print("Default users created.")
    print("Database initialized.")