import os
import cloudinary
import cloudinary.uploader
import io
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from whitenoise import WhiteNoise
from authlib.integrations.flask_client import OAuth
import secrets
import click

# --- App and Extension Initialization ---
app = Flask(__name__)
app.wsgi_app = WhiteNoise(app.wsgi_app, root="static/")
db = SQLAlchemy()
login_manager = LoginManager()
oauth = OAuth()

# --- App Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or f"sqlite:///iedc.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Cloudinary Configuration ---
cloudinary.config(
    cloud_name = os.environ.get('CLOUDINARY_CLOUD_NAME'),
    api_key = os.environ.get('CLOUDINARY_API_KEY'),
    api_secret = os.environ.get('CLOUDINARY_API_SECRET')
)

# --- Google OAuth Configuration ---
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

# --- Connect Extensions to the App ---
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'
oauth.init_app(app)

# --- Database Models (All your class definitions go here) ---
# --- Status Constants ---
STATUS_PENDING = 'pending'
STATUS_APPROVED_BY_SUB = 'approved_by_sub'
STATUS_REJECTED_BY_SUB = 'rejected_by_sub'
STATUS_APPROVED_BY_ADMIN = 'approved_by_admin'
STATUS_REJECTED_BY_ADMIN = 'rejected_by_admin'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    department = db.Column(db.String(100))
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_filename = db.Column(db.Text, nullable=False) 
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    event = db.Column(db.String(150))
    status = db.Column(db.String(30), default=STATUS_PENDING)
    remark = db.Column(db.Text)

class ReviewAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # approve or reject
    remark = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Main Routes (All your @app.route functions go here) ---
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

@app.route('/login/google')
def login_google():
    if not oauth._clients.get('google'):
        flash('Google login is not configured.')
        return redirect(url_for('login'))
    redirect_uri = url_for('auth_google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_google_callback():
    if not oauth._clients.get('google'):
        flash('Google login is not configured.')
        return redirect(url_for('login'))
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo') or {}
        email = userinfo.get('email')
        name = userinfo.get('name') or (email.split('@')[0] if email else None)
        if not email:
            flash('Unable to get email from Google account.')
            return redirect(url_for('login'))
        user = User.query.filter_by(username=email).first()
        if user is None:
            # Create a default student user; department can be set later by admin
            user = User(
                username=email,
                role='student',
                department=None
            )
            # Set a random password hash to satisfy non-null constraint
            user.set_password(secrets.token_urlsafe(32))
            db.session.add(user)
            db.session.commit()
        login_user(user)
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        if user.role == 'sub-admin':
            return redirect(url_for('sub_admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    except Exception as e:
        flash(f'Google login failed: {e}')
        return redirect(url_for('login'))

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
        event_name = request.form.get('event')
        description = request.form['description']
        files = request.files.getlist('images')
        # Basic validation to ensure only images are uploaded
        allowed_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}
        if not current_user.department:
            flash('Your account is missing a department. Please contact an admin to set your department before uploading.')
            return redirect(request.url)
        if not files or files[0].filename == '':
            flash('No files selected')
            return redirect(request.url)
        num_uploaded = 0
        for file in files:
            if file:
                filename_lower = file.filename.lower()
                if not any(filename_lower.endswith(ext) for ext in allowed_extensions) and not (file.mimetype or "").startswith('image/'):
                    flash(f"Skipped non-image file: {file.filename}")
                    continue
                upload_result = cloudinary.uploader.upload(file)
                image_url = upload_result['secure_url']
                new_submission = Submission(
                    image_filename=image_url,
                    description=description,
                    user_id=current_user.id,
                    department=current_user.department,
                    event=event_name
                )
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
    submissions = Submission.query.filter_by(department=current_user.department, status='pending').order_by(Submission.event.asc(), Submission.id.desc()).all()
    grouped = {}
    for s in submissions:
        evt = s.event or 'Uncategorized'
        grouped.setdefault(evt, []).append(s)
    return render_template('sub_admin.html', grouped=grouped)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin': return redirect(url_for('login'))
    submissions = Submission.query.filter_by(status='approved_by_sub').order_by(Submission.department.asc(), Submission.event.asc(), Submission.id.desc()).all()
    # Group by department and event
    grouped = {}
    for s in submissions:
        dept = s.department or 'Unknown'
        evt = s.event or 'Uncategorized'
        grouped.setdefault(dept, {}).setdefault(evt, []).append(s)
    return render_template('admin.html', grouped=grouped)

# Removed unsafe GET route that performed state change. Use POST endpoints below instead.

# --- Sub-admin Review Actions (POST) ---
@app.route('/sub/approve/<int:submission_id>', methods=['POST'])
@login_required
def sub_approve_submission(submission_id):
    if current_user.role != 'sub-admin': return redirect(url_for('login'))
    submission = db.get_or_404(Submission, submission_id)
    if submission.department != current_user.department:
        return redirect(url_for('sub_admin_dashboard'))
    submission.status = STATUS_APPROVED_BY_SUB
    remark_text = request.form.get('remark')
    if remark_text:
        submission.remark = remark_text
    db.session.add(ReviewAction(
        submission_id=submission.id,
        reviewer_id=current_user.id,
        role=current_user.role,
        action='approve',
        remark=remark_text
    ))
    db.session.commit()
    flash('Submission approved and forwarded to main admin.')
    return redirect(url_for('sub_admin_dashboard'))

@app.route('/sub/reject/<int:submission_id>', methods=['POST'])
@login_required
def sub_reject_submission(submission_id):
    if current_user.role != 'sub-admin': return redirect(url_for('login'))
    submission = db.get_or_404(Submission, submission_id)
    if submission.department != current_user.department:
        return redirect(url_for('sub_admin_dashboard'))
    submission.status = STATUS_REJECTED_BY_SUB
    remark_text = request.form.get('remark')
    submission.remark = remark_text
    db.session.add(ReviewAction(
        submission_id=submission.id,
        reviewer_id=current_user.id,
        role=current_user.role,
        action='reject',
        remark=remark_text
    ))
    db.session.commit()
    flash('Submission rejected and remark saved.')
    return redirect(url_for('sub_admin_dashboard'))

@app.route('/export')
@login_required
def export_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.')
        return redirect(url_for('login'))
    try:
        df = pd.read_sql(db.session.query(Submission).statement, db.session.bind)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Submissions', index=False)
            # Review actions sheet with usernames and submission ids
            ra_query = db.session.query(
                ReviewAction.id.label('id'),
                ReviewAction.submission_id.label('submission_id'),
                ReviewAction.reviewer_id.label('reviewer_id'),
                User.username.label('reviewer_username'),
                ReviewAction.role.label('role'),
                ReviewAction.action.label('action'),
                ReviewAction.remark.label('remark'),
                ReviewAction.created_at.label('created_at')
            ).join(User, User.id == ReviewAction.reviewer_id)
            ra_df = pd.read_sql(ra_query.statement, db.session.bind)
            ra_df.to_excel(writer, sheet_name='ReviewActions', index=False)
        output.seek(0)
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name='iedc_submissions.xlsx')
    except Exception as e:
        flash(f"An error occurred while exporting: {e}")
        return redirect(url_for('admin_dashboard'))

# --- Custom Command to Set Up the Database ---
def _initialize_database_if_needed():
    """Create tables and default users if missing. Safe/idempotent."""
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

@app.cli.command("init-db")
def init_db_command():
    """SAFE: Creates tables and default users."""
    _initialize_database_if_needed()

# Alias with underscore (Click auto-exposes both `init_db` and `init-db`)
@app.cli.command("init_db")
def init_db_command_underscore():
    """Alias for init-db."""
    _initialize_database_if_needed()

# Grouped command: `flask db init`
@app.cli.group("db")
def db_group():
    """Database management commands."""
    pass

@db_group.command("init")
def db_init_group():
    _initialize_database_if_needed()

# Optional: bootstrap DB automatically in environments where CLI isn't available
if os.environ.get('AUTO_INIT_DB') == '1':
    with app.app_context():
        try:
            _initialize_database_if_needed()
        except Exception as e:
            print(f"AUTO_INIT_DB failed: {e}")

# --- Safe Migration Command to add review/audit structures ---
@app.cli.command("migrate-review")
def migrate_review_command():
    """Adds ReviewAction table and Submission.remark column if missing."""
    from sqlalchemy import inspect, text
    with app.app_context():
        inspector = inspect(db.engine)
        # Create tables that don't exist (e.g., ReviewAction)
        db.create_all()
        cols = [col['name'] for col in inspector.get_columns('submission')]
        if 'remark' not in cols:
            # Add column in a safe way; SQLite and Postgres support simple ALTER ADD COLUMN
            try:
                db.session.execute(text('ALTER TABLE submission ADD COLUMN remark TEXT'))
                db.session.commit()
                print('Added column submission.remark')
            except Exception as e:
                db.session.rollback()
                print(f'Could not add submission.remark automatically: {e}')
        if 'event' not in cols:
            try:
                db.session.execute(text('ALTER TABLE submission ADD COLUMN event VARCHAR(150)'))
                db.session.commit()
                print('Added column submission.event')
            except Exception as e:
                db.session.rollback()
                print(f'Could not add submission.event automatically: {e}')
        print('migrate-review completed.')

# --- Admin Review Actions (POST) ---
@app.route('/admin/approve/<int:submission_id>', methods=['POST'])
@login_required
def admin_approve_submission(submission_id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    submission = db.get_or_404(Submission, submission_id)
    submission.status = STATUS_APPROVED_BY_ADMIN
    remark_text = request.form.get('remark')
    if remark_text:
        submission.remark = remark_text
    db.session.add(ReviewAction(
        submission_id=submission.id,
        reviewer_id=current_user.id,
        role=current_user.role,
        action='approve',
        remark=remark_text
    ))
    db.session.commit()
    flash('Submission approved by admin.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:submission_id>', methods=['POST'])
@login_required
def admin_reject_submission(submission_id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    submission = db.get_or_404(Submission, submission_id)
    submission.status = STATUS_REJECTED_BY_ADMIN
    remark_text = request.form.get('remark')
    submission.remark = remark_text
    db.session.add(ReviewAction(
        submission_id=submission.id,
        reviewer_id=current_user.id,
        role=current_user.role,
        action='reject',
        remark=remark_text
    ))
    db.session.commit()
    flash('Submission rejected by admin.')
    return redirect(url_for('admin_dashboard'))

# --- HTTP fallback to initialize DB when CLI is unavailable ---
@app.route('/internal/init-db', methods=['POST'])
def http_init_db():
    expected = os.environ.get('INIT_DB_TOKEN')
    token = request.headers.get('X-Init-Token') or request.args.get('token')
    if not expected:
        return ('INIT_DB_TOKEN not set', 400)
    if token != expected:
        return ('Forbidden', 403)
    _initialize_database_if_needed()
    return ('ok', 200)
    