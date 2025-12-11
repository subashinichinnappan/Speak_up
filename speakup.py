from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import secrets
import os

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///speakup_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # user, lawyer, ngo, admin
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(20), unique=True, nullable=False)
    issue_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    is_anonymous = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, under_review, resolved
    location = db.Column(db.String(100))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AwarenessStory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)  # Anonymous message from person
    solution = db.Column(db.Text, nullable=False)  # Solution provided
    category = db.Column(db.String(50), nullable=False)
    approved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Consultation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    lawyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    issue_category = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_anonymous = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def generate_case_id():
    return f"CASE{secrets.token_hex(8).upper()}"

# Routes
@app.route('/')
def home():
    return render_template_string(HOME_TEMPLATE)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        issue_type = request.form.get('issue_type')
        description = request.form.get('description')
        is_anonymous = request.form.get('anonymous') == 'on'
        location = request.form.get('location', '')
        
        case_id = generate_case_id()
        
        new_report = Report(
            case_id=case_id,
            issue_type=issue_type,
            description=description,
            is_anonymous=is_anonymous,
            user_id=current_user.id if current_user.is_authenticated and not is_anonymous else None,
            location=location
        )
        
        db.session.add(new_report)
        db.session.commit()
        
        flash(f'Report submitted successfully! Your case ID is: {case_id}', 'success')
        return redirect(url_for('track_case', case_id=case_id))
    
    return render_template_string(REPORT_TEMPLATE)

@app.route('/track/<case_id>')
def track_case(case_id):
    report = Report.query.filter_by(case_id=case_id).first_or_404()
    return render_template_string(TRACK_TEMPLATE, report=report)

@app.route('/lawlink')
def lawlink():
    lawyers = User.query.filter_by(role='lawyer', verified=True).all()
    ngos = User.query.filter_by(role='ngo', verified=True).all()
    return render_template_string(LAWLINK_TEMPLATE, lawyers=lawyers, ngos=ngos)

@app.route('/consultation/request/<int:expert_id>', methods=['POST'])
def request_consultation(expert_id):
    issue_category = request.form.get('issue_category')
    message = request.form.get('message')
    is_anonymous = request.form.get('anonymous') == 'on'
    
    consultation = Consultation(
        user_id=current_user.id if current_user.is_authenticated and not is_anonymous else None,
        lawyer_id=expert_id,
        issue_category=issue_category,
        message=message,
        is_anonymous=is_anonymous
    )
    
    db.session.add(consultation)
    db.session.commit()
    
    flash('Consultation request submitted successfully!', 'success')
    return redirect(url_for('lawlink'))

@app.route('/awareness')
def awareness():
    stories = AwarenessStory.query.filter_by(approved=True).order_by(AwarenessStory.created_at.desc()).all()
    return render_template_string(AWARENESS_TEMPLATE, stories=stories)

@app.route('/rights')
def rights():
    return render_template_string(RIGHTS_TEMPLATE)

@app.route('/dashboard/transparency')
def transparency_dashboard():
    total_reports = Report.query.count()
    pending = Report.query.filter_by(status='pending').count()
    under_review = Report.query.filter_by(status='under_review').count()
    resolved = Report.query.filter_by(status='resolved').count()
    
    # Issue type statistics
    issue_types = db.session.query(
        Report.issue_type, 
        db.func.count(Report.id)
    ).group_by(Report.issue_type).all()
    
    stats = {
        'total_reports': total_reports,
        'pending': pending,
        'under_review': under_review,
        'resolved': resolved,
        'issue_types': issue_types
    }
    
    return render_template_string(TRANSPARENCY_TEMPLATE, stats=stats)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role not in ['admin', 'ngo']:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    
    reports = Report.query.order_by(Report.created_at.desc()).all()
    stories = AwarenessStory.query.order_by(AwarenessStory.created_at.desc()).all()
    consultations = Consultation.query.order_by(Consultation.created_at.desc()).all()
    
    return render_template_string(
        ADMIN_TEMPLATE, 
        reports=reports, 
        stories=stories,
        consultations=consultations
    )

@app.route('/admin/report/<int:report_id>/update', methods=['POST'])
@login_required
def update_report(report_id):
    if current_user.role not in ['admin', 'ngo']:
        return jsonify({'error': 'Access denied'}), 403
    
    report = Report.query.get_or_404(report_id)
    new_status = request.form.get('status')
    report.status = new_status
    db.session.commit()
    
    flash('Report status updated successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/story/<int:story_id>/approve', methods=['POST'])
@login_required
def approve_story(story_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    story = AwarenessStory.query.get_or_404(story_id)
    story.approved = True
    db.session.commit()
    
    flash('Story approved successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            verified=(role == 'user')  # Auto-verify regular users
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template_string(REGISTER_TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# HTML Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpeakUp+ | Professional Justice Platform</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 1.5rem 5%;
            color: white;
        }
        .navbar h1 { 
            margin-bottom: 0.3rem; 
            font-weight: 700;
        }
        .navbar p {
            opacity: 0.9;
        }
        .container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 5%;
        }
        .section {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        .section h2 {
            color: #2c5282;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background: #f7fafc;
            font-weight: 600;
            color: #2d3748;
        }
        .status-badge {
            padding: 0.4rem 0.9rem;
            border-radius: 16px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-under_review { background: #dbeafe; color: #1e40af; }
        .status-resolved { background: #d1fae5; color: #065f46; }
        .btn-small {
            padding: 0.6rem 1.2rem;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            margin-right: 0.5rem;
            transition: opacity 0.3s;
        }
        .btn-small:hover {
            opacity: 0.8;
        }
        .btn-update { background: #3182ce; color: white; }
        .btn-approve { background: #059669; color: white; }
        select {
            padding: 0.6rem;
            border: 2px solid #e2e8f0;
            border-radius: 6px;
            font-weight: 500;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1> Admin Dashboard</h1>
        <p>Manage reports, stories, and consultations</p>
    </div>

    <div class="container">
        <div class="section">
            <h2> Recent Reports</h2>
            <table>
                <thead>
                    <tr>
                        <th>Case ID</th>
                        <th>Issue Type</th>
                        <th>Status</th>
                        <th>Submitted</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for report in reports %}
                    <tr>
                        <td><strong>{{ report.case_id }}</strong></td>
                        <td>{{ report.issue_type.replace('_', ' ').title() }}</td>
                        <td><span class="status-badge status-{{ report.status }}">{{ report.status.replace('_', ' ').title() }}</span></td>
                        <td>{{ report.created_at.strftime('%Y-%m-%d') }}</td>
                        <td>
                            <form action="/admin/report/{{ report.id }}/update" method="POST" style="display: inline;">
                                <select name="status">
                                    <option value="pending" {% if report.status == 'pending' %}selected{% endif %}>Pending</option>
                                    <option value="under_review" {% if report.status == 'under_review' %}selected{% endif %}>Under Review</option>
                                    <option value="resolved" {% if report.status == 'resolved' %}selected{% endif %}>Resolved</option>
                                </select>
                                <button type="submit" class="btn-small btn-update">Update</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2> Success Stories (Pending Approval)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Category</th>
                        <th>Submitted</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for story in stories %}
                    {% if not story.approved %}
                    <tr>
                        <td><strong>{{ story.title }}</strong></td>
                        <td>{{ story.category.replace('_', ' ').title() }}</td>
                        <td>{{ story.created_at.strftime('%Y-%m-%d') }}</td>
                        <td>
                            <form action="/admin/story/{{ story.id }}/approve" method="POST" style="display: inline;">
                                <button type="submit" class="btn-small btn-approve">Approve</button>
                            </form>
                        </td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Consultation Requests</h2>
            <table>
                <thead>
                    <tr>
                        <th>Issue Category</th>
                        <th>Status</th>
                        <th>Requested</th>
                        <th>Anonymous</th>
                    </tr>
                </thead>
                <tbody>
                    {% for consultation in consultations %}
                    <tr>
                        <td>{{ consultation.issue_category.replace('_', ' ').title() }}</td>
                        <td><span class="status-badge status-{{ consultation.status }}">{{ consultation.status.title() }}</span></td>
                        <td>{{ consultation.created_at.strftime('%Y-%m-%d') }}</td>
                        <td>{{ 'Yes' if consultation.is_anonymous else 'No' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

REGISTER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .form-container {
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 100%;
        }
        h1 {
            color: #2c5282;
            margin-bottom: 0.5rem;
            text-align: center;
            font-weight: 700;
        }
        .subtitle {
            text-align: center;
            color: #718096;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2d3748;
        }
        input, select {
            width: 100%;
            padding: 0.9rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
            font-family: inherit;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #3182ce;
        }
        .btn {
            background: #2c5282;
            color: white;
            padding: 1.1rem;
            border: none;
            border-radius: 8px;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2a4365;
        }
        .links {
            text-align: center;
            margin-top: 1.5rem;
        }
        .links a {
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .alert {
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        .alert-danger { 
            background: #fef2f2; 
            color: #991b1b; 
            border-color: #ef4444;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <h1>Create Account</h1>
        <p class="subtitle">Join SpeakUp+ Platform</p>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form action="/register" method="POST">
            <div class="form-group">
                <label for="username">Username *</label>
                <input type="text" name="username" id="username" required>
            </div>

            <div class="form-group">
                <label for="email">Email *</label>
                <input type="email" name="email" id="email" required>
            </div>

            <div class="form-group">
                <label for="password">Password *</label>
                <input type="password" name="password" id="password" required minlength="6">
            </div>

            <div class="form-group">
                <label for="role">Account Type *</label>
                <select name="role" id="role">
                    <option value="user">Regular User</option>
                    <option value="lawyer">Legal Advisor (Requires Verification)</option>
                    <option value="ngo">Support Organization (Requires Verification)</option>
                </select>
            </div>

            <button type="submit" class="btn">Register</button>
        </form>

        <div class="links">
            Already have an account? <a href="/login">Login here</a><br>
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .form-container {
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
            max-width: 450px;
            width: 100%;
        }
        h1 {
            color: #2c5282;
            margin-bottom: 0.5rem;
            text-align: center;
            font-weight: 700;
        }
        .subtitle {
            text-align: center;
            color: #718096;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2d3748;
        }
        input {
            width: 100%;
            padding: 0.9rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
            font-family: inherit;
        }
        input:focus {
            outline: none;
            border-color: #3182ce;
        }
        .btn {
            background: #2c5282;
            color: white;
            padding: 1.1rem;
            border: none;
            border-radius: 8px;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2a4365;
        }
        .links {
            text-align: center;
            margin-top: 1.5rem;
        }
        .links a {
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .links a:hover {
            text-decoration: underline;
        }
        .alert {
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        .alert-danger { 
            background: #fef2f2; 
            color: #991b1b; 
            border-color: #ef4444;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <h1>Welcome Back</h1>
        <p class="subtitle">Login to SpeakUp+</p>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" required>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" required>
            </div>

            <button type="submit" class="btn">Login</button>
        </form>

        <div class="links">
            Don't have an account? <a href="/register">Register here</a><br>
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
'''

# Initialize Database and Create Tables
def init_db():
    with app.app_context():
        db.create_all()
        
        # Create sample admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@speakup.com',
                password=generate_password_hash('admin123'),
                role='admin',
                verified=True
            )
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created (username: admin, password: admin123)")
        
        # Create sample lawyer if not exists
        if not User.query.filter_by(username='lawyer_demo').first():
            lawyer = User(
                username='lawyer_demo',
                email='lawyer@example.com',
                password=generate_password_hash('lawyer123'),
                role='lawyer',
                verified=True
            )
            db.session.add(lawyer)
            db.session.commit()
            print("✓ Demo lawyer created (username: lawyer_demo, password: lawyer123)")
        
        # Create sample NGO if not exists
        if not User.query.filter_by(username='ngo_demo').first():
            ngo = User(
                username='ngo_demo',
                email='ngo@example.com',
                password=generate_password_hash('ngo123'),
                role='ngo',
                verified=True
            )
            db.session.add(ngo)
            db.session.commit()
            print("✓ Demo NGO created (username: ngo_demo, password: ngo123)")
        
        # Create sample awareness stories if not exists
        if AwarenessStory.query.count() == 0:
            stories_data = [
                {
                    "title": "From Silence to Justice: A Workplace Harassment Resolution",
                    "message": "I endured workplace harassment for 2 years but was too afraid to speak up. My manager made inappropriate comments daily and threatened my job security if I complained. I felt trapped and helpless, watching my mental health deteriorate.",
                    "solution": "Through SpeakUp+, the victim was connected with a verified employment lawyer who documented the case thoroughly. Legal proceedings were initiated, and the company was held accountable. The victim received full compensation, the harasser was terminated, and the company implemented mandatory anti-harassment training. The case took 3 months to resolve successfully.",
                    "category": "workplace_abuse"
                },
                {
                    "title": "Cyberbullying Stopped: Digital Rights Protected",
                    "message": "Someone created fake social media profiles using my photos and posted defamatory content. My reputation was being destroyed online, and I didn't know how to stop it. The cyberbullying escalated to threats against my family.",
                    "solution": "Our cybercrime legal expert filed an immediate complaint with the cyber cell and platforms. Within 2 weeks, all fake profiles were removed, and the perpetrator was identified and prosecuted. The victim received a restraining order and the harasser faced legal consequences including fines and probation.",
                    "category": "cybercrime"
                },
                {
                    "title": "Domestic Violence: Breaking Free and Finding Safety",
                    "message": "I suffered domestic violence for years but had nowhere to turn. I was financially dependent and feared for my children's safety. Every attempt to leave resulted in more violence and threats.",
                    "solution": "SpeakUp+ connected the survivor with a women's rights NGO and legal advisor specializing in domestic violence cases. Emergency shelter was arranged within 24 hours. Legal protection orders were obtained, and the survivor received counseling, legal aid, and financial assistance to rebuild her life independently. The abuser was prosecuted successfully.",
                    "category": "domestic_violence"
                }
            ]
            
            for story_data in stories_data:
                story = AwarenessStory(**story_data, approved=True)
                db.session.add(story)
            
            db.session.commit()
            print("✓ Sample success stories created")

# Run the Application
if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("SpeakUp+ Platform Server Starting...")
    print("="*60)
    print("\n Access the application at: http://localhost:5000")
    print("\n Demo Accounts:")
    print("   Admin: username='admin', password='admin123'")
    print("   Lawyer: username='lawyer_demo', password='lawyer123'")
    print("   NGO: username='ngo_demo', password='ngo123'")
    print("\n" + "="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 1.2rem 5%;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .navbar-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }
        .logo {
            color: white;
            font-size: 1.6rem;
            font-weight: 700;
            text-decoration: none;
            letter-spacing: -0.5px;
        }
        .logo-accent {
            color: #3182ce;
        }
        .nav-links {
            display: flex;
            gap: 2rem;
            align-items: center;
        }
        .nav-links a {
            color: #e2e8f0;
            text-decoration: none;
            transition: color 0.2s;
            font-weight: 500;
            font-size: 0.95rem;
        }
        .nav-links a:hover { color: #3182ce; }
        .hero {
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            color: white;
            padding: 5rem 5%;
            text-align: center;
        }
        .hero h1 {
            font-size: 3rem;
            margin-bottom: 1rem;
            font-weight: 700;
            line-height: 1.2;
        }
        .hero p {
            font-size: 1.25rem;
            margin-bottom: 2.5rem;
            opacity: 0.95;
            max-width: 700px;
            margin-left: auto;
            margin-right: auto;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 4rem 5%;
        }
        .btn-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
        }
        .btn {
            display: inline-block;
            padding: 1.2rem 2rem;
            background: white;
            color: #2c5282;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            text-align: center;
            transition: all 0.3s;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            border: 2px solid transparent;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.15);
            border-color: #3182ce;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }
        .feature-card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            transition: all 0.3s;
            border: 1px solid #e2e8f0;
        }
        .feature-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        .feature-card h3 {
            color: #2d3748;
            margin-bottom: 0.75rem;
            font-weight: 600;
        }
        .feature-card p {
            color: #4a5568;
            line-height: 1.7;
        }
        footer {
            background: #1a202c;
            color: #e2e8f0;
            text-align: center;
            padding: 2.5rem;
            margin-top: 4rem;
        }
        .flash-messages {
            max-width: 1200px;
            margin: 1rem auto;
            padding: 0 5%;
        }
        .alert {
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }
        .alert-success { 
            background: #f0fdf4; 
            color: #166534; 
            border-color: #22c55e;
        }
        .alert-danger { 
            background: #fef2f2; 
            color: #991b1b; 
            border-color: #ef4444;
        }
        .alert-info { 
            background: #eff6ff; 
            color: #1e40af; 
            border-color: #3b82f6;
        }
        .section-title {
            text-align: center;
            margin-bottom: 3rem;
            color: #2d3748;
        }
        .section-title h2 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .section-title p {
            color: #718096;
            font-size: 1.1rem;
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="navbar-content">
            <a href="/" class="logo">SpeakUp<span class="logo-accent">+</span></a>
            <div class="nav-links">
                <a href="/">Home</a>
                <a href="/awareness">Stories</a>
                <a href="/rights">Rights</a>
                <a href="/dashboard/transparency">Dashboard</a>
                {% if current_user.is_authenticated %}
                    {% if current_user.role in ['admin', 'ngo'] %}
                        <a href="/admin/dashboard">Admin</a>
                    {% endif %}
                    <a href="/logout">Logout</a>
                {% else %}
                    <a href="/login">Login</a>
                    <a href="/register">Register</a>
                {% endif %}
            </div>
        </div>
    </nav>

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            <div class="flash-messages">
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            </div>
        {% endif %}
    {% endwith %}

    <section class="hero">
        <h1> Your Voice Matters — Speak Up for Justice</h1>
        <p>A secure, confidential platform connecting individuals with legal experts and support organizations</p>
        <div class="btn-group">
            <a href="/report" class="btn"> Report Issue</a>
            <a href="/lawlink" class="btn"> Legal Support</a>
            <a href="/rights" class="btn"> Know Rights</a>
            <a href="/awareness" class="btn"> View Stories</a>
        </div>
    </section>

    <div class="container">
        <div class="section-title">
            <h2>Why Choose SpeakUp+?</h2>
            <p>Professional, secure, and trusted by thousands</p>
        </div>
        <div class="features">
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Complete Anonymity</h3>
                <p>Your identity is fully protected with enterprise-grade encryption. Report without fear of exposure.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Swift Response</h3>
                <p>Connect with verified legal professionals and support organizations within 24 hours.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Verified Experts</h3>
                <p>All legal professionals undergo thorough background verification for your safety.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Track Progress</h3>
                <p>Monitor case status in real-time with secure, unique tracking identifiers.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Nationwide Impact</h3>
                <p>Join a growing community of voices fighting for justice across regions.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"></div>
                <h3>Confidential Communication</h3>
                <p>Secure messaging system with end-to-end protection for all conversations.</p>
            </div>
        </div>
    </div>

    <footer>
        <p style="font-size: 1.1rem; margin-bottom: 0.5rem;"><strong>SpeakUp+</strong> — Professional Justice Platform</p>
        <p style="opacity: 0.8;">Secure • Confidential • Trusted</p>
        <p style="margin-top: 1rem; opacity: 0.7;">&copy; 2024 SpeakUp+. All rights reserved.</p>
    </footer>
</body>
</html>
'''

REPORT_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Report - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }
        h1 {
            color: #2c5282;
            margin-bottom: 0.5rem;
            font-weight: 700;
        }
        .subtitle {
            color: #718096;
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2d3748;
        }
        select, textarea, input[type="text"] {
            width: 100%;
            padding: 0.9rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s;
            font-family: inherit;
        }
        select:focus, textarea:focus, input[type="text"]:focus {
            outline: none;
            border-color: #3182ce;
        }
        textarea {
            min-height: 150px;
            resize: vertical;
        }
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1rem;
            background: #f7fafc;
            border-radius: 8px;
            border: 2px solid #e2e8f0;
        }
        .checkbox-group input[type="checkbox"] {
            width: auto;
            cursor: pointer;
            width: 18px;
            height: 18px;
        }
        .btn {
            background: #2c5282;
            color: white;
            padding: 1.1rem 2rem;
            border: none;
            border-radius: 8px;
            font-size: 1.05rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #2a4365;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .info-box {
            background: #ebf8ff;
            padding: 1.2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            border-left: 4px solid #3182ce;
        }
        .info-box strong {
            color: #2c5282;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1> Submit Confidential Report</h1>
        <p class="subtitle">Your information is encrypted and secure</p>
        
        <div class="info-box">
            <strong> Privacy Assured:</strong> Enable "Submit Anonymously" to completely protect your identity.
            You'll receive a unique tracking ID to monitor your report status.
        </div>

        <form action="/report" method="POST">
            <div class="form-group">
                <label for="issue_type">Issue Type *</label>
                <select name="issue_type" id="issue_type" required>
                    <option value="">Select issue type...</option>
                    <option value="harassment">Harassment</option>
                    <option value="corruption">Corruption</option>
                    <option value="cybercrime">Cybercrime</option>
                    <option value="discrimination">Discrimination</option>
                    <option value="domestic_violence">Domestic Violence</option>
                    <option value="workplace_abuse">Workplace Abuse</option>
                    <option value="fraud">Fraud</option>
                    <option value="other">Other</option>
                </select>
            </div>

            <div class="form-group">
                <label for="description">Describe the Incident *</label>
                <textarea name="description" id="description" required 
                    placeholder="Please provide detailed information about the incident..."></textarea>
            </div>

            <div class="form-group">
                <label for="location">Location (Optional)</label>
                <input type="text" name="location" id="location" 
                    placeholder="City or region">
            </div>

            <div class="checkbox-group">
                <input type="checkbox" name="anonymous" id="anonymous" checked>
                <label for="anonymous" style="margin-bottom: 0; font-weight: 500;">
                    Submit Anonymously (Recommended)
                </label>
            </div>

            <button type="submit" class="btn">Submit Report Securely</button>
        </form>

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

TRACK_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Track Case - {{ report.case_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #2c5282 0%, #2d3748 100%);
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 3rem;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }
        h1 { 
            color: #2c5282; 
            margin-bottom: 2rem; 
            font-weight: 700;
        }
        .case-id {
            background: #f7fafc;
            padding: 1.2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            font-size: 1.2rem;
            font-weight: 600;
            text-align: center;
            border: 2px solid #e2e8f0;
        }
        .status-badge {
            display: inline-block;
            padding: 0.6rem 1.2rem;
            border-radius: 24px;
            font-weight: 600;
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-under_review { background: #dbeafe; color: #1e40af; }
        .status-resolved { background: #d1fae5; color: #065f46; }
        .info-row {
            padding: 1.2rem 0;
            border-bottom: 1px solid #e2e8f0;
        }
        .info-label {
            font-weight: 600;
            color: #4a5568;
            margin-bottom: 0.4rem;
            font-size: 0.9rem;
        }
        .info-value {
            color: #2d3748;
            font-size: 1.05rem;
        }
        .back-link {
            display: inline-block;
            margin-top: 2rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1> Case Tracking</h1>
        <div class="case-id">Case ID: {{ report.case_id }}</div>
        
        <span class="status-badge status-{{ report.status }}">
            Status: {{ report.status.replace('_', ' ').title() }}
        </span>

        <div class="info-row">
            <div class="info-label">Issue Type</div>
            <div class="info-value">{{ report.issue_type.replace('_', ' ').title() }}</div>
        </div>

        <div class="info-row">
            <div class="info-label">Submitted On</div>
            <div class="info-value">{{ report.created_at.strftime('%B %d, %Y at %I:%M %p') }}</div>
        </div>

        <div class="info-row">
            <div class="info-label">Last Updated</div>
            <div class="info-value">{{ report.updated_at.strftime('%B %d, %Y at %I:%M %p') }}</div>
        </div>

        {% if report.location %}
        <div class="info-row">
            <div class="info-label">Location</div>
            <div class="info-value">{{ report.location }}</div>
        </div>
        {% endif %}

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

LAWLINK_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Legal Support - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 1.5rem 5%;
            color: white;
        }
        .navbar h1 { 
            margin-bottom: 0.3rem; 
            font-weight: 700;
        }
        .navbar p {
            opacity: 0.9;
        }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 5%;
        }
        .section {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        .section h2 {
            color: #2c5282;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        .expert-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        .expert-card {
            background: white;
            border: 2px solid #e2e8f0;
            padding: 1.8rem;
            border-radius: 12px;
            transition: all 0.3s;
        }
        .expert-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
            border-color: #3182ce;
        }
        .expert-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        .expert-avatar {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #2c5282 0%, #3182ce 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
            font-weight: 700;
        }
        .verified-badge {
            color: #059669;
            font-weight: 600;
        }
        .expert-role {
            color: #718096;
            font-size: 0.9rem;
            font-weight: 500;
        }
        .btn {
            background: #ECF0F1;
            color: black;
            padding: 0.9rem 1.5rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            width: 100%;
            margin-top: 1rem;
            transition: background 0.3s;
        }
        .btn:hover { background: #2a4365; }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.6);
            z-index: 1000;
        }
        .modal-content {
            background: white;
            max-width: 600px;
            margin: 5% auto;
            padding: 2.5rem;
            border-radius: 12px;
            max-height: 80vh;
            overflow-y: auto;
        }
        .close {
            float: right;
            font-size: 2rem;
            cursor: pointer;
            color: #718096;
            line-height: 1;
        }
        .close:hover {
            color: #2d3748;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2d3748;
        }
        select, textarea {
            width: 100%;
            padding: 0.9rem;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            font-size: 1rem;
            font-family: inherit;
        }
        textarea { min-height: 120px; }
        select:focus, textarea:focus {
            outline: none;
            border-color: #3182ce;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1> Legal Support Network</h1>
        <p>Connect with verified legal professionals and support organizations</p>
    </div>

    <div class="container">
        <div class="section">
            <h2> Verified Legal Advisors</h2>
            <div class="expert-grid">
                {% for lawyer in lawyers %}
                <div class="expert-card">
                    <div class="expert-header">
                        <div class="expert-avatar">{{ lawyer.username[0].upper() }}</div>
                        <div>
                            <div><strong>{{ lawyer.username }}</strong> <span class="verified-badge">✅</span></div>
                            <div class="expert-role">Legal Advisor</div>
                        </div>
                    </div>
                    <p style="color: #718096; margin-bottom: 1rem;">{{ lawyer.email }}</p>
                    <button class="btn" onclick="openConsultation({{ lawyer.id }}, '{{ lawyer.username }}')">
                        Request Consultation
                    </button>
                </div>
                {% else %}
                <p style="color: #718096;">No verified legal advisors available at the moment.</p>
                {% endfor %}
            </div>
        </div>

        <div class="section">
            <h2> Verified Support Organizations</h2>
            <div class="expert-grid">
                {% for ngo in ngos %}
                <div class="expert-card">
                    <div class="expert-header">
                        <div class="expert-avatar">{{ ngo.username[0].upper() }}</div>
                        <div>
                            <div><strong>{{ ngo.username }}</strong> <span class="verified-badge">✅</span></div>
                            <div class="expert-role">Support Organization</div>
                        </div>
                    </div>
                    <p style="color: #718096; margin-bottom: 1rem;">{{ ngo.email }}</p>
                    <button class="btn" onclick="openConsultation({{ ngo.id }}, '{{ ngo.username }}')">
                        Contact Organization
                    </button>
                </div>
                {% else %}
                <p style="color: #718096;">No verified organizations available at the moment.</p>
                {% endfor %}
            </div>
        </div>

        <a href="/" class="back-link">← Back to Home</a>
    </div>

    <div id="consultationModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2 style="color: #2c5282; margin-bottom: 0.5rem;">Request Consultation</h2>
            <p style="color: #718096; margin-bottom: 1.5rem;">with <strong id="expertName"></strong></p>
            
            <form id="consultationForm" method="POST">
                <div class="form-group">
                    <label for="issue_category">Issue Category *</label>
                    <select name="issue_category" required>
                        <option value="">Select category...</option>
                        <option value="womens_rights">Women's Rights</option>
                        <option value="cybercrime">Cybercrime</option>
                        <option value="property_disputes">Property Disputes</option>
                        <option value="labor_rights">Labor Rights</option>
                        <option value="domestic_violence">Domestic Violence</option>
                        <option value="consumer_rights">Consumer Rights</option>
                        <option value="other">Other</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="message">Your Message *</label>
                    <textarea name="message" required placeholder="Describe your situation in detail..."></textarea>
                </div>

                <div class="form-group">
                    <label style="font-weight: 500;">
                        <input type="checkbox" name="anonymous"> Request Anonymously
                    </label>
                </div>

                <button type="submit" class="btn">Submit Request</button>
            </form>
        </div>
    </div>

    <script>
        function openConsultation(expertId, expertName) {
            document.getElementById('consultationModal').style.display = 'block';
            document.getElementById('expertName').textContent = expertName;
            document.getElementById('consultationForm').action = '/consultation/request/' + expertId;
        }

        function closeModal() {
            document.getElementById('consultationModal').style.display = 'none';
        }

        window.onclick = function(event) {
            const modal = document.getElementById('consultationModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
'''

AWARENESS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Success Stories - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 2rem 5%;
            color: white;
            text-align: center;
        }
        .navbar h1 { 
            margin-bottom: 0.5rem; 
            font-weight: 700;
        }
        .navbar p {
            opacity: 0.9;
        }
        .container {
            max-width: 900px;
            margin: 2rem auto;
            padding: 0 5%;
        }
        .story-card {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        .story-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #f0f0f0;
        }
        .story-category {
            background: #2c5282;
            color: white;
            padding: 0.5rem 1.2rem;
            border-radius: 24px;
            font-size: 0.9rem;
            font-weight: 600;
        }
        .story-date {
            color: #718096;
            font-size: 0.9rem;
            font-weight: 500;
        }
        .story-title {
            font-size: 1.6rem;
            color: #2d3748;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        .story-section {
            margin-bottom: 1.5rem;
        }
        .story-section-title {
            color: #2c5282;
            font-weight: 600;
            margin-bottom: 0.75rem;
            font-size: 1.1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .story-message {
            background: #f7fafc;
            padding: 1.5rem;
            border-radius: 8px;
            line-height: 1.8;
            color: #4a5568;
            border-left: 4px solid #cbd5e0;
            font-style: italic;
            margin-bottom: 1.5rem;
        }
        .story-solution {
            background: #f0fdf4;
            padding: 1.5rem;
            border-radius: 8px;
            line-height: 1.8;
            color: #166534;
            border-left: 4px solid #22c55e;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .no-stories {
            text-align: center;
            padding: 4rem 2rem;
            background: white;
            border-radius: 12px;
            border: 1px solid #e2e8f0;
        }
        .no-stories h2 {
            color: #2d3748;
            margin-bottom: 1rem;
        }
        .no-stories p {
            color: #718096;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1>💬 Success Stories</h1>
        <p>Anonymous voices that found justice and solutions</p>
    </div>

    <div class="container">
        {% if stories %}
            {% for story in stories %}
            <div class="story-card">
                <div class="story-header">
                    <span class="story-category">{{ story.category.replace('_', ' ').title() }}</span>
                    <span class="story-date">{{ story.created_at.strftime('%B %d, %Y') }}</span>
                </div>
                <h2 class="story-title">{{ story.title }}</h2>
                
                <div class="story-section">
                    <div class="story-section-title">
                         Anonymous Message
                    </div>
                    <div class="story-message">
                        "{{ story.message }}"
                    </div>
                </div>

                <div class="story-section">
                    <div class="story-section-title">
                         Solution Provided
                    </div>
                    <div class="story-solution">
                        {{ story.solution }}
                    </div>
                </div>
            </div>
            {% endfor %}
        {% else %}
            <div class="no-stories">
                <h2>No stories available yet</h2>
                <p style="margin-top: 1rem;">
                    Check back soon for inspiring stories of justice and successful outcomes!
                </p>
            </div>
        {% endif %}

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

RIGHTS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Know Your Rights - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 2rem 5%;
            color: white;
            text-align: center;
        }
        .navbar h1 {
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .navbar p {
            opacity: 0.9;
        }
        .container {
            max-width: 1000px;
            margin: 2rem auto;
            padding: 0 5%;
        }
        .rights-section {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        .rights-section h2 {
            color: #2c5282;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        .right-item {
            padding: 1.5rem;
            border-left: 4px solid #3182ce;
            background: #f7fafc;
            margin-bottom: 1.2rem;
            border-radius: 8px;
        }
        .right-item h3 {
            color: #2d3748;
            margin-bottom: 0.75rem;
            font-weight: 600;
        }
        .right-item p {
            color: #4a5568;
            line-height: 1.7;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .help-section {
            background: #ebf8ff;
            border: 2px solid #3182ce;
        }
        .help-section h2 {
            color: #2c5282;
        }
        .help-section ul {
            padding-left: 2rem;
            line-height: 2;
            color: #2d3748;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1> Know Your Rights</h1>
        <p>Essential legal knowledge for everyone</p>
    </div>

    <div class="container">
        <div class="rights-section">
            <h2>Fundamental Rights</h2>
            
            <div class="right-item">
                <h3>Right to Equality</h3>
                <p>You have the right to be treated equally regardless of race, gender, religion, or background. Discrimination is prohibited by law.</p>
            </div>

            <div class="right-item">
                <h3>Right to Freedom</h3>
                <p>You have freedom of speech, expression, assembly, and movement. These rights can only be restricted under specific legal circumstances.</p>
            </div>

            <div class="right-item">
                <h3>Right Against Exploitation</h3>
                <p>You are protected against human trafficking, forced labor, and child labor. No one can exploit you against your will.</p>
            </div>

            <div class="right-item">
                <h3>Right to Privacy</h3>
                <p>Your personal information and privacy are protected. Unauthorized surveillance or data collection is illegal.</p>
            </div>
        </div>

        <div class="rights-section">
            <h2>Women's Rights</h2>
            
            <div class="right-item">
                <h3>Protection from Domestic Violence</h3>
                <p>The Domestic Violence Act protects women from physical, emotional, and economic abuse. You can file complaints and seek protection orders.</p>
            </div>

            <div class="right-item">
                <h3>Workplace Rights</h3>
                <p>You have the right to equal pay, safe working conditions, and protection from sexual harassment at the workplace.</p>
            </div>

            <div class="right-item">
                <h3>Right to Property</h3>
                <p>Women have equal rights to inherit and own property. Denial of property rights is legally challengeable.</p>
            </div>
        </div>

        <div class="rights-section">
            <h2>Cyber Rights</h2>
            
            <div class="right-item">
                <h3>Protection from Cyberbullying</h3>
                <p>Online harassment, stalking, and bullying are punishable offenses. You can report such incidents to cybercrime cells.</p>
            </div>

            <div class="right-item">
                <h3>Data Protection</h3>
                <p>Your personal data must be protected. Unauthorized sharing or selling of your data is illegal.</p>
            </div>

            <div class="right-item">
                <h3>Digital Privacy</h3>
                <p>You have the right to privacy in digital communications. Hacking and unauthorized access are criminal offenses.</p>
            </div>
        </div>

        <div class="rights-section">
            <h2>Consumer Rights</h2>
            
            <div class="right-item">
                <h3>Right to Information</h3>
                <p>You have the right to complete information about products and services before purchase.</p>
            </div>

            <div class="right-item">
                <h3>Right to Redressal</h3>
                <p>If you face issues with products or services, you can seek compensation through consumer courts.</p>
            </div>
        </div>

        <div class="rights-section help-section">
            <h2> Need Help? 📞</h2>
            <p style="margin-bottom: 1rem; color: #2d3748;">If your rights are being violated, you can:</p>
            <ul>
                <li>File a confidential report on SpeakUp+ anonymously</li>
                <li>Connect with verified legal professionals</li>
                <li>Contact support organizations for immediate assistance</li>
                <li>Reach out to police or legal aid services</li>
            </ul>
        </div>

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

TRANSPARENCY_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f7fafc;
        }
        .navbar {
            background: #1a202c;
            padding: 2rem 5%;
            color: white;
            text-align: center;
        }
        .navbar h1 {
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .navbar p {
            opacity: 0.9;
        }
        .container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 0 5%;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            text-align: center;
            border: 1px solid #e2e8f0;
        }
        .stat-number {
            font-size: 3rem;
            font-weight: 700;
            color: #2c5282;
            margin-bottom: 0.5rem;
        }
        .stat-label {
            color: #718096;
            font-size: 1.1rem;
            font-weight: 500;
        }
        .chart-section {
            background: white;
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
            border: 1px solid #e2e8f0;
        }
        .chart-section h2 {
            color: #2c5282;
            margin-bottom: 1.5rem;
            font-weight: 700;
        }
        .issue-bar {
            margin-bottom: 1.2rem;
        }
        .issue-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2d3748;
        }
        .progress-bar {
            height: 32px;
            background: #e2e8f0;
            border-radius: 16px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #2c5282 0%, #3182ce 100%);
            display: flex;
            align-items: center;
            padding-left: 1rem;
            color: white;
            font-weight: 600;
        }
        .back-link {
            display: inline-block;
            margin-top: 1.5rem;
            color: #3182ce;
            text-decoration: none;
            font-weight: 600;
        }
        .back-link:hover {
            text-decoration: underline;
        }
        .impact-section {
            background: #ebf8ff;
            border: 2px solid #3182ce;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <h1> Transparency Dashboard</h1>
        <p>Real-time statistics and impact metrics</p>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ stats.total_reports }}</div>
                <div class="stat-label">Total Reports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.pending }}</div>
                <div class="stat-label">Pending</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.under_review }}</div>
                <div class="stat-label">Under Review</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ stats.resolved }}</div>
                <div class="stat-label">Resolved</div>
            </div>
        </div>

        <div class="chart-section">
            <h2>Reports by Issue Type</h2>
            {% for issue_type, count in stats.issue_types %}
            <div class="issue-bar">
                <div class="issue-label">
                    <span>{{ issue_type.replace('_', ' ').title() }}</span>
                    <span>{{ count }} reports</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ (count / stats.total_reports * 100) if stats.total_reports > 0 else 0 }}%">
                        {{ "%.1f"|format((count / stats.total_reports * 100) if stats.total_reports > 0 else 0) }}%
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="chart-section impact-section">
            <h2 style="color: #2c5282;">Our Impact</h2>
            <p style="line-height: 1.8; color: #2d3748;">
                SpeakUp+ has empowered {{ stats.total_reports }} individuals to report injustices safely and confidentially.
                {% if stats.resolved > 0 %}
                We've successfully facilitated resolution for {{ stats.resolved }} cases, bringing justice and support to those who needed it most.
                {% endif %}
                Together, we're building a professional community where every voice matters and justice prevails through proper channels.
            </p>
        </div>

        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
'''

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - SpeakUp+</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-