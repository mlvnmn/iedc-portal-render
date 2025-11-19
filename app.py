import os
import cloudinary
import cloudinary.uploader
import io
import pandas as pd
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

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False) 
    password_hash = db.Column(db.String(200), nullable=False)
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
    department = db.Column(db.String(100), nullable=False, index=True)
    status = db.Column(db.String(20), default='pending', index=True)

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            if user.role == 'admin': return redirect(url_for('admin_dashboard'))
            elif user.role == 'sub-admin': return redirect(url_for('sub_admin_dashboard'))
            else: return redirect(url_for('student_dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

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

@app.route('/sub_admin_dashboard')
@login_required
def sub_admin_dashboard():
    if current_user.role != 'sub-admin': return redirect(url_for('login'))
    submissions = Submission.query.filter_by(department=current_user.department, status='pending').all()
    return render_template('sub_admin.html', submissions=submissions)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    selected_department = request.args.get('department')

    if selected_department:
        # A department is selected, show the images for that department
        submissions = Submission.query.filter_by(
            status='approved_by_sub',
            department=selected_department
        ).all()
        return render_template('admin.html', submissions=submissions, department=selected_department)
    else:
        # No department selected, show the "folders"
        departments = db.session.query(Submission.department).filter_by(status='approved_by_sub').distinct().all()
        # departments is a list of tuples, e.g., [('Computer Science',), ('Biotechnology',)]
        # We convert it to a simple list of strings
        department_names = [d[0] for d in departments]
        return render_template('admin.html', departments=department_names)

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

@app.route('/export')
@login_required
def export_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.'); return redirect(url_for('login'))
    try:
        df = pd.read_sql(db.session.query(Submission).statement, db.session.bind)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Submissions', index=False)
        output.seek(0)
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name='iqac_submissions.xlsx')
    except Exception as e:
        flash(f"An error occurred while exporting: {e}"); return redirect(url_for('admin_dashboard'))

# --- Custom Command to Set Up the Database (Demo Version) ---
@app.cli.command("init-db")
def init_db_command():
    """Creates tables and default users for the Demo."""
    db.create_all()

    users_to_create = [
        {'username': 'admin', 'role': 'admin', 'department': 'College', 'password': 'admin123'},
        {'username': 'teacher_cs', 'role': 'sub-admin', 'department': 'Computer Science', 'password': '123'},
        {'username': 'student_cs', 'role': 'student', 'department': 'Computer Science', 'password': '123'},
        {'username': 'teacher_bio', 'role': 'sub-admin', 'department': 'Biotechnology', 'password': '123'},
        {'username': 'student_bio', 'role': 'student', 'department': 'Biotechnology', 'password': '123'},
        {'username': 'teacher_default', 'role': 'sub-admin', 'department': 'Not Specified', 'password': '123'}
    ]

    for user_data in users_to_create:
        if User.query.filter_by(username=user_data['username']).first() is None:
            print(f"Creating user: {user_data['username']}...")
            user = User(
                username=user_data['username'],
                role=user_data['role'],
                department=user_data['department']
            )
            user.set_password(user_data['password'])
            db.session.add(user)
        else:
            print(f"User {user_data['username']} already exists.")

    db.session.commit()
    print("Database initialization complete.")