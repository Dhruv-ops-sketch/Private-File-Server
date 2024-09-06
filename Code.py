from flask import Flask, request, redirect, url_for, flash, render_template_string, send_from_directory, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
import os

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

    @staticmethod
    def get(user_id):
        return User.query.get(int(user_id))

    @staticmethod
    def find_by_username(username):
        return User.query.filter_by(username=username).first()

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('File', validators=[InputRequired()])
    submit = SubmitField('Upload')

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password=password_hash)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful, you can now login.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists', 'danger')
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <title>Register</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Register</h1>
                <form method="post" class="mt-3">
                    {{ form.hidden_tag() }}
                    <div class="form-group">
                        {{ form.username.label }}
                        {{ form.username(class_='form-control') }}
                    </div>
                    <div class="form-group">
                        {{ form.password.label }}
                        {{ form.password(class_='form-control') }}
                    </div>
                    <div class="form-group">
                        {{ form.submit(class_='btn btn-primary') }}
                    </div>
                </form>
                <a href="{{ url_for('login') }}" class="btn btn-link">Already have an account? Login here</a>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    ''', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.find_by_username(username)
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password', 'danger')
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <title>Login</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                <form method="post" class="mt-3">
                    {{ form.hidden_tag() }}
                    <div class="form-group">
                        {{ form.username.label }}
                        {{ form.username(class_='form-control') }}
                    </div>
                    <div class="form-group">
                        {{ form.password.label }}
                        {{ form.password(class_='form-control') }}
                    </div>
                    <div class="form-group">
                        {{ form.submit(class_='btn btn-primary') }}
                    </div>
                </form>
                <a href="{{ url_for('register') }}" class="btn btn-link">Don't have an account? Register here</a>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    ''', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
            <title>File Server</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">File Server</h1>
                <form method="post" enctype="multipart/form-data" class="mt-3">
                    {{ form.hidden_tag() }}
                    <div class="form-group">
                        {{ form.file.label }}
                        {{ form.file(class_='form-control-file') }}
                    </div>
                    <div class="form-group">
                        {{ form.submit(class_='btn btn-primary') }}
                    </div>
                </form>
                <h2 class="mt-5">Files</h2>
                <ul class="list-group">
                {% for filename in files %}
                    <li class="list-group-item d-flex justify-content-between align-items-center">
                        <a href="{{ url_for('download_file', filename=filename) }}">{{ filename }}</a>
                        <form method="post" action="{{ url_for('delete_file', filename=filename) }}" class="ml-3">
                            <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                        </form>
                    </li>
                {% endfor %}
                </ul>
                <a href="{{ url_for('logout') }}" class="btn btn-secondary mt-3">Logout</a>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.4/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    ''', files=files, form=UploadForm())

@app.route('/', methods=['POST'])
@login_required
def upload_file():
    form = UploadForm()
    if form.validate_on_submit():
        file = form.file.data
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(url_for('home'))
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully', 'success')
            return redirect(url_for('home'))

@app.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f'File {filename} deleted successfully', 'success')
    else:
        flash(f'File {filename} not found', 'danger')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
