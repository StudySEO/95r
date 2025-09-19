import os
import base64
import requests
from io import BytesIO
from PIL import Image

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

import google.generativeai as genai

# Load environment variables from .env file
load_dotenv()

# --- App Initialization and Configuration ---
app = Flask(__name__)

# Secret key for session management and security tokens
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_default_strong_secret_key')

# Database configuration (using SQLite for simplicity)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration for password reset
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your email
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your email app password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Google OAuth Configuration
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')

# --- Gemini API Configuration ---
try:
    genai.configure(api_key=os.environ["GEMINI_API_KEY"])
except KeyError:
    print("GEMINI_API_KEY not found in environment variables.")


# --- Extensions Initialization ---
db = SQLAlchemy(app)
mail = Mail(app)
oauth = OAuth(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login page if user is not authenticated

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True) # Nullable for SSO users
    name = db.Column(db.String(100))
    google_id = db.Column(db.String(100), unique=True, nullable=True)

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Password Reset Token Generation ---
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='password-reset-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
    except:
        return False
    return email

# --- Google SSO Configuration ---
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)


# --- Routes ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user or not user.password or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('profile'))

    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists.')
        return redirect(url_for('login'))

    new_user = User(
        email=email,
        name=name,
        password=generate_password_hash(password, method='pbkdf2:sha256')
    )
    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)

    return redirect(url_for('profile'))

@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    google_id = user_info['id']
    user_email = user_info['email']
    user_name = user_info['name']

    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=user_email).first()
        if not user:
            # Create a new user if they don't exist
            user = User(
                google_id=google_id,
                email=user_email,
                name=user_name,
            )
            db.session.add(user)
        else:
            # Link Google ID to existing email account
            user.google_id = google_id

    db.session.commit()
    login_user(user)
    return redirect(url_for('profile'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(email)
            reset_url = url_for('reset_with_token', token=token, _external=True)
            # This is a placeholder for the email sending logic
            # In a real app, you would format an HTML email here
            # and send it using the `mail` object.
            # Example:
            # msg = Message("Password Reset Request", recipients=[email])
            # msg.body = f"Click here to reset your password: {reset_url}"
            # mail.send(msg)
            flash(f'A password reset link has been sent to your email. The link is: {reset_url}')
        else:
            flash('That email does not exist in our records.')
        return redirect(url_for('login'))
    return render_template('login.html', show_forgot_password=True)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        email = confirm_token(token)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first_or_404()
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Your password has been updated!', 'success')
        login_user(user)
        return redirect(url_for('profile'))

    return render_template('reset_token.html', token=token)


# --- Gemini API Service Endpoints ---

@app.route('/api/enhance-prompt', methods=['POST'])
@login_required
def enhance_prompt():
    prompt = request.json.get('prompt')
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash-preview-05-20')
        system_instruction = "You are an expert prompt engineer for an AI image generation model. Rewrite the user's simple prompt into a rich, detailed, and artistic prompt. Focus on cinematic lighting, composition, and specific details. Return only the rewritten prompt itself, without any introductory text."
        response = model.generate_content(
            f"Rewrite this prompt: {prompt}",
            generation_config=genai.types.GenerationConfig(
                candidate_count=1,
                max_output_tokens=200,
            ),
            system_instruction=system_instruction
        )
        return jsonify({'enhancedPrompt': response.text})
    except Exception as e:
        return jsonify({'error': f"Failed to enhance prompt: {e}"}), 500


@app.route('/api/generate-image', methods=['POST'])
@login_required
def generate_image():
    prompt = request.json.get('prompt')
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400

    try:
        api_key = os.environ.get("GEMINI_API_KEY")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/imagen-3.0-generate-002:predict?key={api_key}"
        payload = {
            "instances": [{"prompt": prompt}],
            "parameters": {"sampleCount": 1}
        }
        response = requests.post(url, json=payload)
        response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)

        result = response.json()
        base64_image = result['predictions'][0]['bytesBase64Encoded']

        return jsonify({'base64Image': base64_image})
    except Exception as e:
        return jsonify({'error': f"Failed to generate image: {e}"}), 500


@app.route('/api/edit-image', methods=['POST'])
@login_required
def edit_image():
    prompt = request.json.get('prompt')
    image_data_b64 = request.json.get('imageData')

    if not prompt or not image_data_b64:
        return jsonify({'error': 'Prompt and image data are required'}), 400

    try:
        model = genai.GenerativeModel('gemini-2.5-flash-image-preview')

        image_bytes = base64.b64decode(image_data_b64)
        image = Image.open(BytesIO(image_bytes))

        # Combine the user's edit instruction with the image
        response = model.generate_content([prompt, image])

        # The response part contains the image data
        image_part = response.parts[0]
        edited_image_bytes = image_part.inline_data.data

        # Re-encode to base64 to send back to the client
        edited_image_b64 = base64.b64encode(edited_image_bytes).decode('utf-8')

        return jsonify({'base64Image': edited_image_b64})
    except Exception as e:
        return jsonify({'error': f"Failed to edit image: {e}"}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Creates the database tables if they don't exist
    app.run(debug=True)
