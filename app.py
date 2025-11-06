import os
import cloudinary
import cloudinary.uploader
import io
import zipfile
import pandas as pd
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file, session
from sqlalchemy import text
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from whitenoise import WhiteNoise

# --- App and Extension Initialization ---
app = Flask(__name__)
app.wsgi_app = WhiteNoise(app.wsgi_app, root="static/")
db = SQLAlchemy()
login_manager = LoginManager()

# --- App Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')

# --- Cloudinary Configuration ---
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET')
)

# --- Connect Extensions to the App ---
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Database Models (Simplified) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False) 
    password_hash = db.Column(db.String(200), nullable=False) # No longer nullable
    role = db.Column(db.String(20), nullable=False, default='student')
    department = db.Column(db.String(100), default='Not Specified')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.Text, nullable=False) 
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('submissions', lazy=True))
    department = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Login & Auth Routes (Simplified) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))

        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Dashboard Routes ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/student_dashboard', methods=['GET', 'POST'])
@login_required
def student_dashboard():
    if current_user.role != 'student': return redirect(url_for('login'))
    if request.method == 'POST':
        description = request.form['description']
        files = request.files.getlist('images')
        if not files or files[0].filename == '':
            flash('No files selected'); return redirect(request.url)
        num_uploaded = 0
        for file in files:
            if file:
                upload_result = cloudinary.uploader.upload(file)
                new_submission = Submission(image_filename=upload_result['secure_url'], description=description, user_id=current_user.id, department=current_user.department)
                db.session.add(new_submission)
                num_uploaded += 1
        db.session.commit()
        flash(f'Successfully uploaded {num_uploaded} images!')
        return redirect(url_for('student_dashboard'))
    return render_template('student.html')

@app.route('/teacher_dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        return redirect(url_for('login'))
    
    submissions = Submission.query.filter_by(
        department=current_user.department, 
        status='pending'
    ).all()
    
    return render_template('teacher.html', submissions=submissions)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    submissions = Submission.query.all()
    
    return render_template('admin.html', submissions=submissions)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        department = request.form['department']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is None:
            new_user = User(username=username, role=role, department=department)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!')
            return redirect(url_for('admin_dashboard'))
        
        flash('Username already exists.')
        return redirect(url_for('add_user'))
        
    return render_template('add_user.html')

# --- Action Routes ---
@app.route('/download_approved_submissions')
@login_required
def download_approved_submissions():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.')
        return redirect(url_for('login'))

    approved_submissions = Submission.query.filter_by(status='approved').all()

    if not approved_submissions:
        flash('No approved submissions to download.')
        return redirect(url_for('admin_dashboard'))

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for submission in approved_submissions:
            department_folder = submission.department
            image_filename = submission.image_filename.split('/')[-1]
            description_filename = f"{os.path.splitext(image_filename)[0]}.txt"

            # Add image to zip
            try:
                image_response = requests.get(submission.image_filename, stream=True)
                image_response.raise_for_status()
                zf.writestr(f"{department_folder}/{image_filename}", image_response.content)
            except requests.exceptions.RequestException as e:
                app.logger.error(f"Error downloading image {submission.image_filename}: {e}")
                continue

            # Add description to zip
            zf.writestr(f"{department_folder}/{description_filename}", submission.description)

    memory_file.seek(0)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name='approved_submissions.zip'
    )

@app.route('/download_image')
@login_required
def download_image():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.'); return redirect(url_for('login'))
    image_url = request.args.get('url')
    if not image_url:
        flash('No image URL provided.'); return redirect(url_for('admin_dashboard'))
    try:
        response = requests.get(image_url, stream=True)
        response.raise_for_status()
        return send_file(
            io.BytesIO(response.content),
            mimetype=response.headers['Content-Type'],
            as_attachment=True,
            download_name='downloaded_image.jpg'
        )
    except requests.exceptions.RequestException as e:
        flash(f"An error occurred while downloading the image: {e}"); return redirect(url_for('admin_dashboard'))

@app.route('/reject/<int:submission_id>', methods=['POST'])
@login_required
def reject_submission(submission_id):
    if current_user.role != 'teacher':
        return redirect(url_for('login'))
    
    submission = db.get_or_404(Submission, submission_id)
    
    if submission.department == current_user.department:
        submission.status = 'rejected'
        db.session.commit()
        flash('Submission rejected.')
    
    return redirect(url_for('teacher_dashboard'))

@app.route('/approve/<int:submission_id>', methods=['POST'])
@login_required
def approve_submission(submission_id):
    if current_user.role != 'teacher':
        return redirect(url_for('teacher_dashboard'))
    
    submission = db.get_or_404(Submission, submission_id)
    
    if submission.department == current_user.department:
        submission.status = 'approved'
        db.session.commit()
        flash('Submission approved and forwarded to main admin.')
    
    return redirect(url_for('teacher_dashboard'))

# --- Custom Database Command (Safe) ---
@app.cli.command("init-db")
def init_db_command():
    """SAFE: Creates tables and default users."""
    
    # The "DROP SCHEMA" line is now GONE.
    
    db.create_all() 
    if User.query.filter_by(username='admin').first() is None:
        print("Creating default users...")
        users = [
            User(username='admin', role='admin', department='College'),
            User(username='teacher_cs', role='teacher', department='Computer Science'),
            User(username='student_cs', role='student', department='Computer Science')
        ]
        passwords = ['admin123', 'teacher123', 'student123']
        for i, user in enumerate(users):
            user.set_password(passwords[i])
            db.session.add(user)
        db.session.commit()
        print("Default users created.")
    print("Database initialized.")