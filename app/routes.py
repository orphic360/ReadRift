from tokenize import group
from flask import Flask, Blueprint, render_template, redirect, url_for, request, flash, send_from_directory, current_app, url_for, abort, session, make_response, g
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from .models import Group, GroupMember, db, User, UploadedFile, CommunityChat, Book, Notification, Message, ChatHistory, Favorites, UserActivity, WordLookup, Note, UserRole, Badge, UserBadge, UserStats, Genre
from .forms import LoginForm, RegistrationForm, UploadFileForm, AddBookForm, UpdateAccountForm, ChangePasswordForm, UserRoleForm
from . import db, login_manager
from .gamification import BADGE_MISSIONS
import os
import requests
from flask import jsonify
from functools import wraps
from flask_socketio import emit, join_room
from app import socketio
from datetime import datetime, timedelta
from sqlalchemy import func
import uuid
import google.generativeai as genai
import PyPDF2
from PyPDF2 import PdfReader
import nltk
from .book_analyzer import BookAnalyzer
from transformers import pipeline
import traceback
from .utils.activity_loggers import log_activity
from datetime import datetime, timedelta
from sqlalchemy.orm import joinedload
from nltk.corpus import wordnet

nltk.download('wordnet')
nltk.download('punkt')
nltk.download('averaged_perceptron_tagger')
nltk.download('stopwords')

# Configure Gemini API
genai.configure(api_key='AIzaSyBOIMAxbRULe4sN3dOPfpXBWWuA_Jz5xLI')

# Create a model instance
model = genai.GenerativeModel('gemini-1.0-pro')

GEMINI_API_KEY = "AIzaSyBOIMAxbRULe4sN3dOPfpXBWWuA_Jz5xLI"  # Replace with your actual API key
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.0-pro:generateContent"
main_bp = Blueprint('main', __name__)

def get_ai_response(message):
    try:
        # Prepare payload for the Gemini API
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": message  # Changed from user_message to message
                        }
                    ]
                }
            ]
        }
        
        # Make the API call
        response = requests.post(
            'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.0-pro:generateContent',
            headers={
                'Authorization': f'Bearer {os.environ.get("GEMINI_API_KEY")}',
                'Content-Type': 'application/json'
            },
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            return data['candidates'][0]['content']['parts'][0]['text']
        else:
            raise Exception(f"API Error: {response.status_code}")
            
    except Exception as e:
        print(f"Error in get_ai_response: {str(e)}")
        return "Sorry, I encountered an error while processing your request."

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be an admin to access this page.', 'danger')
            return redirect(url_for('main.home'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            if current_user.role not in roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('main.user_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@main_bp.route('/api/heartbeat', methods=['GET'])
@login_required
def heartbeat():
    # Update the last activity time
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "ok"})

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
        except Exception as e:
            db.session.rollback()
            print("Database Commit Error:", e)
            flash('Failed to register. Please try again.', 'danger')
        return redirect(url_for('main.login'))
    else:
        print("Form validation failed:", form.errors)
    return render_template('register.html', form=form)

@main_bp.route('/user-activity', methods=['GET', 'POST'])
@login_required
@admin_required
def user_activity():
    form = RegistrationForm()
    try:
        # Get filter parameters from request
        page = request.args.get('page', 1, type=int)
        user_id = request.args.get('user_id', type=int)
        activity_type = request.args.get('type')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        
        # Start building the query
        query = UserActivity.query.join(
            User, UserActivity.user_id == User.id
        ).options(db.joinedload(UserActivity.user))
        
        # Apply filters if provided
        if user_id:
            query = query.filter(UserActivity.user_id == user_id)
        if activity_type:
            query = query.filter(UserActivity.activity_type == activity_type)
        if date_from:
            query = query.filter(UserActivity.timestamp >= date_from)
        if date_to:
            next_day = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(UserActivity.timestamp < next_day)
        
        # Order and paginate the results
        pagination = query.order_by(
            UserActivity.timestamp.desc()
        ).paginate(page=page, per_page=20, error_out=False)
        
        # Get unique activity types for filter dropdown
        activity_types = db.session.query(
            UserActivity.activity_type
        ).distinct().all()
        
        return render_template(
            'admin/user_activity.html',
            activities=pagination,
            activity_types=[t[0] for t in activity_types if t[0]],  # Filter out None values
            current_filters={
                'user_id': user_id,
                'type': activity_type,
                'date_from': date_from,
                'date_to': date_to
            },
            form=form
        )
    
    except Exception as e:
        current_app.logger.error(f"Error in user_activity: {str(e)}", exc_info=True)
        flash('An error occurred while retrieving activity logs.', 'danger')
        return redirect(url_for('main.admin_dashboard'))  

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print(f"User found: {user.username}")
            if check_password_hash(user.password, form.password.data):
                print("Password matches")
                login_user(user, remember=form.remember_me.data)
                
                # Log successful login
                log_activity(
                    user_id=user.id,
                    activity_type='login',
                    request=request,
                    details='User logged in successfully'
                )
                
                # Update user's activity tracking
                today = datetime.utcnow().date()
                last_active = user.last_active
                
                if last_active:
                    days_since_last_active = (today - last_active).days
                    
                    if days_since_last_active == 0:
                        # User already logged in today, no updates needed
                        pass
                    elif days_since_last_active == 1:
                        # User logged in yesterday, increment streak
                        user.streak += 1
                        log_activity(
                            user_id=user.id,
                            activity_type='streak_updated',
                            request=request,
                            details=f'Streak updated to {user.streak} days'
                        )
                    else:
                        # User missed one or more days, reset streak to 1
                        user.streak = 1
                        log_activity(
                            user_id=user.id,
                            activity_type='streak_reset',
                            request=request,
                            details='Login after missing days, streak reset to 1'
                        )
                    
                    # Update last active date
                    user.last_active = today
                    
                    # Increment active days if this is a new day
                    if days_since_last_active > 0:
                        user.active_days += 1
                else:
                    # First time user is logging in
                    user.last_active = today
                    user.active_days = 1
                    user.streak = 1
                    log_activity(
                        user_id=user.id,
                        activity_type='first_login',
                        request=request,
                        details='First time user logged in'
                    )
                
                # Create a new activity record for this login
                try:
                    activity = UserActivity(
                        user_id=user.id,
                        duration_minutes=0,  # Will be updated by the middleware
                        activity_type='session_start',
                        ip_address=request.remote_addr,
                        user_agent=request.user_agent.string if request.user_agent else None,
                        details='User session started'
                    )
                    db.session.add(activity)
                    db.session.commit()
                    print(f"New activity record created for user {user.username}")
                except Exception as e:
                    db.session.rollback()
                    print(f"Error creating activity record: {str(e)}")
                    log_activity(
                        user_id=user.id,
                        activity_type='error',
                        request=request,
                        details=f'Error creating activity record: {str(e)}'
                    )
                
                flash('Logged in successfully!', 'success')
                return redirect(url_for('main.user_dashboard'))
            else:
                print("Invalid password")
                # Log failed login attempt
                log_activity(
                    user_id=None,
                    activity_type='failed_login',
                    request=request,
                    details=f'Failed login attempt for email: {form.email.data}'
                )
        else:
            print("User not found")
            # Log failed login attempt with non-existent email
            log_activity(
                user_id=None,
                activity_type='failed_login',
                request=request,
                details=f'Login attempt with non-existent email: {form.email.data}'
            )
        flash('Invalid email or password.', 'danger')
    else:
        print("Form validation failed:", form.errors)
        # Log form validation failure
        log_activity(
            user_id=None,
            activity_type='login_validation_failed',
            request=request,
            details=f'Form validation failed: {form.errors}'
        )
    return render_template('login.html', form=form)

@main_bp.route('/admin/dashboard')
@login_required
@role_required([UserRole.SYSTEM_ADMIN, UserRole.CONTENT_MANAGER])
def admin_dashboard():
     # Get statistics
    user_count = User.query.count()
    book_count = Book.query.count()
    
    # Get all users
    users = User.query.order_by(User.username).all()
    print(f"DEBUG: Found {len(users)} users")  # Check console output
    for user in users:
        print(f"User: {user.username}, Role: {user.role}")  # Check user roles
        
    if current_user.role == UserRole.CONTENT_MANAGER:
        return render_template('admin/dashboard.html',
                            user_count=user_count,
                            book_count=book_count,
                            UserRole=UserRole,
                            users=users)
    else:  # SYSTEM_ADMIN
        from flask_wtf import FlaskForm
        from wtforms import StringField, PasswordField, SelectField, BooleanField
        from wtforms.validators import DataRequired, Email, Length

        class SimpleForm(FlaskForm):
            username = StringField('Username', validators=[DataRequired()])
            email = StringField('Email', validators=[DataRequired(), Email()])
            password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
            confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
            role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])
            is_active = BooleanField('Active', default=True)

        form = SimpleForm()
        return render_template('admin_dashboard.html',
                            user_count=user_count,
                            book_count=book_count,
                            users=users,
                            UserRole=UserRole,  # Pass users to content manager template
                            form=form)

@main_bp.route('/admin/users')
@login_required
@role_required([UserRole.SYSTEM_ADMIN])
def user_list():
    users = User.query.all()
    return render_template('admin/user_list.html', users=users)

@main_bp.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.SYSTEM_ADMIN])
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('main.user_list'))
    return render_template('admin/user_form.html', form=form, title='Add User')

@main_bp.route('/admin/books')
@login_required
@role_required([UserRole.SYSTEM_ADMIN, UserRole.CONTENT_MANAGER])
def manage_books():
    page = request.args.get('page', 1, type=int)
    books = Book.query.order_by(Book.id.desc()).paginate(page=page, per_page=10)
    return render_template('admin/manage_books.html', books=books)


@main_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main_bp.route('/about')
def about():
    return render_template('about.html')

@main_bp.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('main.admin_dashboard'))
    uploaded_docs = UploadedFile.query.filter_by(user_id=current_user.id).all()
    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)

    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.created_at.desc()).all()
    return render_template('user_dashboard.html', 
    username=current_user.username,
    notification_count=notification_count,
    notifications=notifications,
    notes=notes,
    user_initial=user_initial,
    uploaded_docs=uploaded_docs)


@main_bp.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    # Notifications for navbar
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)

    username = current_user.username
    user_initial = username[0].upper() if username else ""

    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['pdf_file']

        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and file.filename.lower().endswith('.pdf'):
            filename = secure_filename(file.filename)
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

            if not os.path.exists(filepath):
                file.save(filepath)
                uploaded_file = UploadedFile(filename=filename, user_id=current_user.id)
                db.session.add(uploaded_file)
                db.session.commit()
                flash(f'{filename} uploaded successfully!', 'success')
            else:
                flash('File already exists.', 'warning')

            return redirect(url_for('.upload_document'))
        else:
            flash('Invalid file type. Please upload a PDF.', 'danger')

    uploaded_files = UploadedFile.query.filter_by(user_id=current_user.id).all()
    return render_template('rifter.html', 
    uploaded_files=uploaded_files,
   username=current_user.username,
    user_initial=user_initial,
    notification_count=notification_count,
    notifications=notifications)

@main_bp.route('/uploads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename)

@main_bp.route('/view_pdf/<filename>')
@login_required
def view_pdf(filename):
    # Verify the file exists and belongs to the user
    file = UploadedFile.query.filter_by(filename=filename, user_id=current_user.id).first_or_404()
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        flash('File not found.', 'danger')
        return redirect(url_for('main.upload_document'))
    
    # Send the file with PDF MIME type
    return send_from_directory(
        current_app.config['UPLOAD_FOLDER'],
        filename,
        as_attachment=False,
        mimetype='application/pdf'
    )    
        
@main_bp.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = UploadedFile.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)  # Forbidden if not the owner
    
    try:
        # Delete file from filesystem
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Delete record from database
        db.session.delete(file)
        db.session.commit()
        flash('File deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting file.', 'danger')
    
    return redirect(url_for('main.upload_document'))

@main_bp.route('/explore')
@login_required
def explore():
    # Check if user has completed the genre wizard
    if not current_user.has_completed_wizard:
        return redirect(url_for('main.genre_wizard'))
    
    q = request.args.get('q', '')
    genre_filter = request.args.get('genre', '')
    genre = None  # Initialize genre to None
    
    # Get all genres from the database
    all_genres = Genre.query.all()
    
    # Get recommended books based on user's genre preferences
    recommended_books = []
    if current_user.genre_preferences:
        preferred_genres = [g.strip() for g in current_user.genre_preferences.split(',')]
        for genre_name in preferred_genres:
            genre = Genre.query.filter_by(name=genre_name).first()
            if genre:
                recommended_books.extend(genre.books)
    
    # Filter books based on search and genre filter
    books_query = Book.query
    if q:
        books_query = books_query.filter(Book.title.ilike(f'%{q}%'))
    if genre_filter:
        genre = Genre.query.filter_by(name=genre_filter).first()  # This is where genre is defined
        if genre:
            books_query = books_query.join(Book.genres).filter(Genre.id == genre.id)
    
    filtered_books = books_query.distinct().all()
    
    # Get books grouped by genre for the genre sections
    genre_books = {}
    for genre in all_genres:
        genre_books[genre.name] = genre.books[:8]  # Limit to 8 books per genre
    
    username = current_user.username
    user_initial = username[0].upper() if username else ""
    
    # Notifications for navbar
    notifications = Notification.query.filter_by(
        user_id=current_user.id, 
        is_read=False
    ).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    
    return render_template('user_explore.html',
        books=filtered_books,
        recommended_books=recommended_books,
        genre_books=genre_books,
        genres=[g.name for g in all_genres],
        username=username,
        user_initial=user_initial,
        notification_count=notification_count,
        notifications=notifications)
            
@main_bp.route('/explore/genre-wizard', methods=['GET', 'POST'])
@login_required
def genre_wizard():
    form = AddBookForm()  # Initialize the form here
    form.genres.choices = [(genre.id, genre.name) for genre in Genre.query.all()]

    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)

    if request.method == 'POST':
        selected_genres = request.form.getlist('genres')
        if len(selected_genres) > 0:
            # Convert genre IDs to names
            genres = Genre.query.filter(Genre.id.in_(selected_genres)).all()
            genre_names = [genre.name for genre in genres]
            current_user.genre_preferences = ','.join(genre_names)
            current_user.has_completed_wizard = True  # <-- Add this line

            db.session.commit()
            flash('Your genre preferences have been saved!', 'success')

            return redirect(url_for('main.explore'))
        flash('Please select at least one genre', 'warning')

    genres = Genre.query.all()  # Fetch genres for rendering
    return render_template('genre_wizard.html', form=form, genres=genres,
                           notifications=notifications,
                           notification_count=notification_count,
                           username=username,
                           user_initial=user_initial)



@main_bp.route('/home')
@login_required
def home():
    query = request.args.get('q', '').strip()
    genre = request.args.get('genre', '').strip()

     # Build the base query
    books_query = Book.query

    if query:
        books_query = books_query.filter(Book.title.ilike(f"%{query}%"))
    if genre:
        books_query = books_query.join(Book.genres).filter(Genre.name == genre)
    
     # Get all unique genres for the dropdown
    all_genres = Genre.query.order_by(Genre.name).all()
    genres = [genre.name for genre in all_genres]
    
    # Fetch all books or filtered books
    if query or genre:
        # Show only books matching the search query
       most_popular_books = books_query.all()
       readers_choice_books = []  # Or use the same filtered list, or none
    else:
        # Featured books for "Most Popular"
        most_popular_books = Book.query.filter_by(is_featured=True).all()
    
        # Books with most views for "Readers' Choice" (no filtering by featured)
        readers_choice_books = (
        Book.query
        .filter(Book.views > 0)
        .order_by(Book.views.desc())
        .limit(8)
        .all()
    )


    # User info for navbar
    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    
    
    return render_template(
        "user_home.html",
        most_popular_books=most_popular_books,
        readers_choice_books=readers_choice_books,
        genres=genres,
        username=username,
        user_initial=user_initial,
        notifications=notifications,
        notification_count=notification_count,
        selected_genre=genre 
    )

@main_bp.route('/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return jsonify({'success': True})

@main_bp.route('/rifter', methods=['GET'])
@login_required
def rifter():
    username = current_user.username
    user_initial = username[0].upper() if username else ""


    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    return render_template('rifter.html',
    current_app=current_app, 
    username=username,
    user_initial=user_initial,
    notifications=notifications,
    notification_count=notification_count)

@main_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()  # Get JSON payload from the request
    user_message = data.get("message")

    if not user_message:
        return jsonify({"error": "Message is required"}), 400

    # Get or create conversation ID
    conversation_id = session.get('conversation_id')
    if not conversation_id:
        conversation_id = str(uuid.uuid4())
        session['conversation_id'] = conversation_id

    try:
        # Save user message
        user_chat = ChatHistory(
            user_id=current_user.id,
            conversation_id=conversation_id,
            content=user_message,
            is_user=True,
            timestamp=datetime.utcnow()
        )
        db.session.add(user_chat)
        db.session.commit()

        # Prepare payload for the Gemini API
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": user_message}
                    ]
                }
            ]
        }

        # Send request to the Gemini API
        headers = {"Content-Type": "application/json"}
        response = requests.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            json=payload,
            headers=headers
        )
        print("Request Payload:", payload)
        print("Response Status Code:", response.status_code)
        print("Response Data:", response.json())

        response_data = response.json()

        # Extract AI response text
        ai_response = (
            response_data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "No response from AI.")
        )

        # Save AI response
        ai_message = ChatHistory(
            user_id=current_user.id,
            conversation_id=conversation_id,
            content=ai_response,
            is_user=False,
            timestamp=datetime.utcnow()
        )
        db.session.add(ai_message)
        db.session.commit()

        return jsonify({
            "response": ai_response,
            'conversation_id': conversation_id
        })

    except Exception as e:
        print("Error:", str(e))  # Debugging: Print the error
        return jsonify({"error": str(e)}), 500

@main_bp.route('/get_history')
@login_required
def get_history():
    # Get distinct conversations
    conversations = db.session.query(
        ChatHistory.conversation_id,
        func.min(ChatHistory.timestamp).label('start_time'),
        func.count().label('message_count')
    ).filter_by(user_id=current_user.id).group_by(ChatHistory.conversation_id).order_by(func.min(ChatHistory.timestamp).desc()).all()
    
    return jsonify([{
        'id': conv.conversation_id,
        'start_time': conv.start_time.isoformat(),
        'message_count': conv.message_count
    } for conv in conversations])


@main_bp.route('/view_conversation/<conversation_id>')
@login_required
def view_conversation(conversation_id):
    # Get all messages for this conversation
    messages = ChatHistory.query.filter_by(
        user_id=current_user.id,
        conversation_id=conversation_id
    ).order_by(ChatHistory.timestamp.asc()).all()
    
    return jsonify([{
        'id': msg.id,
        'content': msg.content,
        'timestamp': msg.timestamp.isoformat(),
        'is_user': msg.is_user
    } for msg in messages])

@main_bp.route('/set_conversation', methods=['POST'])
@login_required
def set_conversation():
    data = request.get_json()
    session['conversation_id'] = data.get('conversation_id')
    return jsonify({'success': True})

@main_bp.route('/delete_conversation/<conversation_id>', methods=['POST'])
@login_required
def delete_conversation(conversation_id):
    # Delete all messages for this conversation
    ChatHistory.query.filter_by(
        user_id=current_user.id,
        conversation_id=conversation_id
    ).delete()
    db.session.commit()
    return jsonify({'success': True})

@main_bp.route('/new_conversation', methods=['POST'])
@login_required
def new_conversation():
    # Clear the session's conversation ID
    session['conversation_id'] = None
    return jsonify({'success': True})

# ---admin---
@main_bp.route('/admin/users/manage', methods=['GET', 'POST'])
@login_required
@role_required([UserRole.SYSTEM_ADMIN])
def admin_manage_users():

    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if the email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
        else:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
        return redirect(url_for('main.admin_dashboard'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users, form=form)


@main_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('main.user_dashboard'))

    user_to_delete = User.query.get(user_id)
    if user_to_delete:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('main.admin_dashboard'))

@main_bp.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('main.user_dashboard'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('main.admin_dashboard'))

    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        is_admin = request.form.get('is_admin', 'off') == 'on'
        user.is_admin = is_admin
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('main.admin_dashboard'))

    return render_template('update_user.html', user=user)


# Community Page - Displays groups
@main_bp.route('/community', methods=['GET'])
@login_required
def community():
    """
    Fetches all groups and filters the groups the user is a member of
    to render on the community page.
    """
    groups = Group.query.all()  # Fetch all groups
    user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()  # Fetch groups the user is a member of
    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    return render_template('community.html', 
    groups=groups, 
    user_groups=user_groups,
    notification_count=notification_count,
    notifications=notifications,
    user_initial=user_initial)


# Handle Group Creation
@main_bp.route('/create_group', methods=['POST'])
@login_required
def create_group():
    """
    Handles logic for creating a new group.
    Checks if the group name is provided, then adds it to the database.
    """
    group_name = request.form.get('group_name')
    description = request.form.get('description', '')

    if not group_name:
        flash('Group name is required.', 'danger')
        return redirect(url_for('main.community'))

    # Check if group already exists
    if Group.query.filter_by(name=group_name).first():
        flash('Group with this name already exists.', 'danger')
        return redirect(url_for('main.community'))

    new_group = Group(name=group_name, description=description, creator_id=current_user.id)
    db.session.add(new_group)
    db.session.commit()
    flash('Group created successfully!', 'success')
    return redirect(url_for('main.community'))


# Handle Joining a Group
@main_bp.route('/join_group/<int:group_id>', methods=['POST'])
@login_required
def join_group(group_id):
    user_groups = GroupMember.query.filter_by(user_id=current_user.id).all()  # Fetch groups the user is a member of
    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    group = Group.query.get_or_404(group_id)
    """
    Allows a user to join a group if they aren't already a member of it.
    """
    if GroupMember.query.filter_by(group_id=group.id, user_id=current_user.id).first():
        flash('You are already a member of this group.', 'info')
        return redirect(url_for('main.community'))
    # Add new member
    new_member = GroupMember(group_id=group.id, user_id=current_user.id)
    db.session.add(new_member)
    db.session.commit()

    join_room(f"group_{group.id}")
    socketio.emit(
        'user_joined',
        {'username': current_user.username, 'group_id': group.id},
        room=f"group_{group.id}"
    )

    flash('You have joined the group!', 'success')
    return redirect(url_for('main.group_chat', group_id=group.id),
                    user_groups=user_groups,
                    notification_count=notification_count,
                    notifications=notifications,
                    user_initial=user_initial)



@main_bp.route('/group/<int:group_id>/chat', methods=['GET', 'POST'])
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    messages = CommunityChat.query.filter_by(group_id=group_id).order_by(CommunityChat.timestamp).all()

    members = GroupMember.query.filter_by(group_id=group_id).all()
    users = [User.query.get(member.user_id) for member in members]
    
    # Get notifications for the current user
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)

    username = current_user.username
    user_initial = username[0].upper() if username else ""


    if request.method == 'POST':
        message = request.form.get('message')
        if message:
            new_message = CommunityChat(group_id=group_id, user_id=current_user.id, message=message)
            db.session.add(new_message)
            db.session.commit()
            flash('Message sent!', 'success')
        else:
            flash('Message cannot be empty.', 'danger')
            
        return render_template('group_chat.html', group=group, messages=messages, users=users, notification_count=notification_count, user_initial=user_initial)

    # For GET requests, always render the chat page
    return render_template('group_chat.html', group=group, messages=messages, users=users, notification_count=notification_count, user_initial=user_initial)

@main_bp.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    if group.creator_id != current_user.id:
        abort(403)  # Forbidden

    # Delete all group memberships
    GroupMember.query.filter_by(group_id=group.id).delete()
    # (Optional) If you have messages or other related models, delete them too:
    # Message.query.filter_by(group_id=group.id).delete()
     # Delete all messages for this group
    CommunityChat.query.filter_by(group_id=group_id).delete()

    db.session.delete(group)
    db.session.commit()
    flash('Group deleted successfully.', 'success')
    return redirect(url_for('main.community'))

@main_bp.route('/group/<int:group_id>/message/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(group_id, message_id):
    message = CommunityChat.query.get_or_404(message_id)
    if message.user_id != current_user.id:
        abort(403)
    db.session.delete(message)
    db.session.commit()
    flash('Message deleted!', 'success')
    return redirect(url_for('main.group_chat', group_id=group_id))

@main_bp.route('/group/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    membership = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash('You left the group.', 'info')
    else:
        flash('You are not a member of this group.', 'warning')
    return redirect(url_for('main.community'))


@main_bp.route('/admin/books/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_book():
    form = AddBookForm()
    form.genres.choices = [(g.id, g.name) for g in Genre.query.order_by('name')]

    print("Form data:", {
        "title": form.title.data,
        "author": form.author.data,
        "description": form.description.data,
        "book_file": form.book_file.data,
        "cover_image": form.cover_image.data,
        "genre": form.new_genre.data,
        "is_featured": form.is_featured.data
    })
    if form.validate_on_submit():
        # Get data from form
        title = form.title.data
        author = form.author.data
        description = form.description.data
        book_file = form.book_file.data
        cover_image = form.cover_image.data

        # Handle new genres
        if form.new_genre.data:
            for genre_name in [g.strip() for g in form.new_genre.data.split(',')]:
                if genre_name:  # Skip empty strings
                    genre = Genre.query.filter_by(name=genre_name).first()
                    if not genre:  # Only add if genre doesn't exist
                        genre = Genre(name=genre_name)
                        db.session.add(genre)
                        db.session.commit()

        if not all([title, author, book_file]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('main.add_book'))

        books_folder = os.path.join(current_app.root_path, 'static', 'uploads', 'books')
        covers_folder = os.path.join(current_app.root_path, 'static', 'uploads', 'covers')
        os.makedirs(books_folder, exist_ok=True)
        os.makedirs(covers_folder, exist_ok=True)

        # Save book file
        book_filename = secure_filename(book_file.filename)
        book_save_path = os.path.join(books_folder, book_filename)
        book_file.save(book_save_path)
        book_file_relpath = f'uploads/books/{book_filename}'  # for storing in DB

        # Save cover image
        image_url = None
        if cover_image:
            image_filename = secure_filename(cover_image.filename)
            image_save_path = os.path.join(covers_folder, image_filename)
            cover_image.save(image_save_path)
            image_url = f'uploads/covers/{image_filename}'  # for storing in DB

        new_book = Book(
            title=title,
            author=author,
            description=description,
            file_path=book_file_relpath,
            image_url=image_url,
            added_by=current_user.id,
            is_featured=form.is_featured.data,
            genre=form.new_genre.data
        )
                
        # Add any new genres that were just created
        if form.new_genre.data:
            for genre_name in [g.strip() for g in form.new_genre.data.split(',')]:
                if genre_name:
                    genre = Genre.query.filter_by(name=genre_name).first()
                    if genre and genre not in new_book.genres:
                        new_book.genres.append(genre)

        db.session.add(new_book)
        db.session.commit()
        flash('Book added successfully!', 'success')
        
        users = User.query.all()
        for user in users:
            notification = Notification(user_id=user.id, message=f"New book uploaded: {new_book.title}")
            db.session.add(notification)
        db.session.commit()    
        return redirect(url_for('main.manage_books'))
    
    else:
        print("Form validation failed:", form.errors)        
        return render_template('admin/add_book.html', form=form)

@main_bp.route('/admin/books/<int:book_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    
    # Delete the book file
    if os.path.exists(book.file_path):
        os.remove(book.file_path)
    
    # Delete the cover image if it exists
    if book.image_url:
        image_path = os.path.join(current_app.root_path, 'static', book.image_url.split('/static/')[-1])
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(book)
    db.session.commit()
    
    flash('Book deleted successfully!', 'success')
    return redirect(url_for('main.manage_books'))


@main_bp.route('/book/<int:book_id>')
@login_required
def view_book(book_id):
    book = Book.query.get_or_404(book_id)
    book.views += 1
    db.session.commit()
    
    # Get the relative path for the static URL
    relative_path = os.path.relpath(book.file_path, current_app.config['UPLOAD_FOLDER'])
    static_path = os.path.join('uploads', 'books', os.path.basename(relative_path))
     # Check if the file exists
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'books', os.path.basename(relative_path))
    if not os.path.exists(file_path):
        abort(404)
    
    return render_template('book_viewer.html', book=book, static_path=static_path)

@main_bp.route('/books/<int:book_id>/read')
@login_required
def read_book(book_id):
    book = Book.query.get_or_404(book_id)
    book.views = (book.views or 0) + 1
    db.session.commit()

    notification_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()

    username = current_user.username
    user_initial = username[0].upper() if username else ""


    return render_template('read.html', 
        book=book,
        notification_count=notification_count,
        user_initial=user_initial)
@main_bp.route('/books')
@login_required
def books():
    books = Book.query.all()
    return render_template('books.html', books=books)

@main_bp.route('/update_progress/<int:book_id>', methods=['POST'])
@login_required
def update_progress(book_id):
    last_page = request.form.get('last_page', type=int)
    total_pages = request.form.get('total_pages', type=int)

    progress = UserBookProgress.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if not progress:
        progress = UserBookProgress(user_id=current_user.id, book_id=book_id)
        db.session.add(progress)
     # Check if book is being marked as completed
    if last_page == total_pages and progress.last_page != total_pages:
        # This is a new completion
        book = Book.query.get(book_id)
        if book:
            # Import the gamification functions
            from .gamification import complete_book
            complete_book(current_user, total_pages)

    progress.last_page = last_page
    progress.total_pages = total_pages
    progress.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'success': True})

@main_bp.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if request.method == 'POST':
        content = request.form['content']
        note = Note(user_id=current_user.id, content=content)
        db.session.add(note)
        db.session.commit()
        flash('Note saved!')
        return jsonify({'success': True})
    
    notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.created_at.desc()).all()
    return jsonify([{
        'content': note.content,
        'created_at': note.created_at.strftime('%Y-%m-%d %H:%M')
    } for note in notes])
@main_bp.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if note:
        db.session.delete(note)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Note not found'}), 404

from .models import Favorites  # Add this import at the top

@main_bp.route('/favorites', methods=['GET', 'POST'])
@login_required
def favorites():
    if request.method == 'POST':
        data = request.get_json()
        book_id = data.get('book_id')
        if book_id:
            # Check if the book is already favorited
            existing_favorite = Favorites.query.filter_by(
                user_id=current_user.id,
                book_id=book_id
            ).first()
            
            if not existing_favorite:
                favorite = Favorites(
                    user_id=current_user.id,
                    book_id=book_id
                )
                db.session.add(favorite)
                db.session.commit()
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': 'Book already in favorites'})
        
        return jsonify({'status': 'error', 'message': 'Book ID not provided'})
    
    username = current_user.username
    user_initial = username[0].upper() if username else ""

    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)
    
    favorites = get_user_favorites(current_user.id)
    return render_template('fav.html', 
        favorites=favorites,
        notification_count=notification_count,
        notifications=notifications,
        user_initial=user_initial)

def get_user_favorites(user_id):
    favorites = Favorites.query.filter_by(user_id=user_id).all()
    favorite_books = []
    for favorite in favorites:
        book = Book.query.get(favorite.book_id)
        if book:
            cover_image = getattr(book, 'cover_image', 'default_cover.jpg')  # Default cover if not present
            favorite_books.append({
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'image_url': book.image_url
            })
    return favorite_books
    
@main_bp.route('/unfavorite/<int:book_id>', methods=['POST'])
@login_required
def unfavorite_book(book_id):
    try:
        favorite = Favorites.query.filter_by(user_id=current_user.id, book_id=book_id).first()
        
        if not favorite:
            return jsonify({"message": "Book is not in favorites"}), 400
        
        db.session.delete(favorite)
        db.session.commit()
        
        return jsonify({"message": "Book removed from favorites successfully"})
        
    except Exception as e:
        print("Error in unfavorite_book:", str(e))
        return jsonify({"error": str(e)}), 500

@main_bp.route('/api/user/activity', methods=['GET'])
@login_required
def get_user_activity():
    # Get current week's activities
    current_week = datetime.utcnow().isocalendar()[1]
    activities = UserActivity.query.filter_by(
        user_id=current_user.id,
        week_number=current_week
    ).all()
    
    # Process the data
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    visit_counts = [0] * 7
    time_spent_seconds = [0] * 7
    
    for activity in activities:
        day_index = activity.visit_date.weekday()  # 0=Monday, 6=Sunday
        visit_counts[day_index] += 1
        time_spent_seconds[day_index] += activity.duration_minutes * 60
    
    return jsonify({
        'days': days,
        'visitCounts': visit_counts,
        'timeSpent': time_spent_seconds
    })

@main_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    notification_count = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).count()

    username = current_user.username
    user_initial = username[0].upper() if username else ""
    
    account_form = UpdateAccountForm()
    password_form = ChangePasswordForm()

    if account_form.submit.data and account_form.validate_on_submit():
        print("Updating account with:", account_form.username.data, account_form.email.data)
        current_user.username = account_form.username.data
        current_user.email = account_form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('main.settings'))

    if password_form.submit.data and password_form.validate_on_submit():
        if current_user.check_password(password_form.current_password.data):
            current_user.set_password(password_form.new_password.data)
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('main.settings'))
        else:
            flash('Current password is incorrect', 'danger')

    elif request.method == 'GET':
        account_form.username.data = current_user.username
        account_form.email.data = current_user.email

    return render_template('settings.html', 
                         account_form=account_form, 
                         password_form=password_form,
                         notification_count=notification_count,
                         username=current_user.username,
                         user_initial=user_initial)


def extract_text_from_pdf(file_path):
    try:
        print(f"Attempting to extract text from: {file_path}")
        
        # Check if file exists and is accessible
        if not os.path.exists(file_path):
            print(f"File not found at {file_path}")
            return ""
        
        # Normalize the path
        file_path = os.path.abspath(file_path)
        
        # Try different methods to extract text
        try:
            # Method 1: Using pdfplumber
            text = ""
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
            
            if text.strip():
                print(f"Extracted text from PDF: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with pdfplumber: {str(e)}")
        
        try:
            # Method 2: Using PyPDF2
            from PyPDF2 import PdfReader
            reader = PdfReader(file_path)
            text = ""
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            
            if text.strip():
                print(f"Extracted text from PyPDF2: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with PyPDF2: {str(e)}")
        
        try:
            # Method 3: Using pdf2text
            from pdf2text import extract_text
            text = extract_text(file_path)
            if text.strip():
                print(f"Extracted text from pdf2text: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with pdf2text: {str(e)}")
        
        print("No content extracted from PDF using any method")
        return ""
    
    except Exception as e:
        print(f"Error extracting text from PDF: {str(e)}")
        return ""

@main_bp.route('/analyze_book', methods=['POST'])
def analyze_book():
    try:
        data = request.json
        book_path = data.get('book_path')
        question = data.get('question')
        function_type = data.get('function_type', 'general')
        
        print(f"Received request with book_path: {book_path}")
        print(f"Question: {question}")
        print(f"Function type: {function_type}")
        
        if not book_path:
            return jsonify({'error': 'Book path not provided'}), 400
        
        if not question:
            return jsonify({'error': 'Question not provided'}), 400
        
        # Check if file exists
        if not os.path.exists(book_path):
            print(f"File not found at {book_path}")
            return jsonify({'error': f'File not found at {book_path}'}), 404
        
        # Extract text from PDF
        book_content = extract_text_from_pdf(book_path)
        
        print(f"Extracted content length: {len(book_content)} characters")
         # Record the word lookup
        if question:
            word = question.lower().strip()
            lookup = WordLookup.query.filter_by(user_id=current_user.id, word=word).first()
            if lookup:
                lookup.count += 1
            else:
                lookup = WordLookup(user_id=current_user.id, word=word)
                db.session.add(lookup)
            db.session.commit()
        
        if not book_content.strip():
            print("No content extracted from PDF")
            return jsonify({'error': 'No content extracted from PDF'}), 400
        
        # Process based on function type
        if function_type == 'definition':
            answer = get_definition(question, book_content)
        elif function_type == 'synonyms':
            answer = get_synonyms(question, book_content)
        elif function_type == 'explanation':
            answer = get_explanation(question, book_content)
        elif function_type == 'translation':
            answer = get_translation(question, book_content)
        elif function_type == 'cultural':
            answer = get_cultural_reference(question, book_content)
        else:  # general
            answer = get_general_analysis(question, book_content)
        
        return jsonify({
            'answer': answer
        })

    except Exception as e:
        print(f"Error in analyze_book: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_ai_response(prompt, function_type='general'):
    try:
        # Create a structured prompt for Gemini
        system_prompt = """
        You are a helpful book analysis assistant. 
        Your responses should be:
        1. Concise and clear
        2. Based on the book content
        3. Relevant to the user's query
        4. Free of unnecessary information
        """
        
        # Generate response using Gemini
        response = model.generate_content(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_output_tokens=1024
        )
        
        # Get the text from the response
        answer = ""
        for candidate in response.candidates:
            if candidate.content:
                for part in candidate.content.parts:
                    if part.text:
                        answer += part.text
                        break
        
        if not answer:
            return "No response generated"
        
        return answer
    except Exception as e:
        print(f"Error in get_ai_response: {str(e)}")
        return f"Error generating response: {str(e)}"

def get_definition(word, content=None):
    url = f"https://api.dictionaryapi.dev/api/v2/entries/en/{word}"
    response = requests.get(url)
    definitions = response.json()
    
    if not definitions or 'title' in definitions:
        return "No definition found."
    
    return definitions[0]['meanings'][0]['definitions'][0]['definition']

def get_synonyms(word, content=None):
    synonyms = set()
    for syn in wordnet.synsets(word):
        for lemma in syn.lemmas():
            synonyms.add(lemma.name())
    
    if not synonyms:
        return "No synonyms found."
    
    # Return up to 7 synonyms, or fewer if not available
    return ', '.join(list(synonyms)[:7])

def get_explanation(term, content):
    context = get_context(term, content)
    prompt = f"""
    You are a knowledgeable book analysis assistant.
    Provide a detailed and insightful explanation of the concept '{term}' using examples from this book:
    {context}
    Ensure the explanation is clear, engaging, and easy to understand for readers of all levels.
    """
    response = model.generate_content(prompt)
    answer = ""
    for candidate in response.candidates:
        if candidate.content:
            for part in candidate.content.parts:
                if part.text:
                    # Improve readability by adding formatting
                    answer += f"\n\n{part.text.strip()}"
                    break
    return answer.strip()

from translate import Translator

def get_translation(text, content=None):
    # Create a translator object for Urdu
    translator = Translator(to_lang="ur")
    
    try:
        # Translate the text to Urdu
        translation = translator.translate(text)
        return translation
    except Exception as e:
        return f"Translation error: {str(e)}"


def get_cultural_reference(term, content):
    context = get_context(term, content)
    prompt = f"""
    You are a helpful book analysis assistant.
    Explain any cultural or historical references related to '{term}' in this book:
    {context}
    Include:
    1. The historical context
    2. Cultural significance
    3. Relevance to the book's themes
    """
    response = model.generate_content(prompt)
    answer = ""
    for candidate in response.candidates:
        if candidate.content:
            for part in candidate.content.parts:
                if part.text:
                    answer += part.text
                    break
    return answer

def get_general_analysis(question, content):
    context = get_context(question, content)
    prompt = f"""
    You are a helpful book analysis assistant.
    Analyze the following question in the context of this book:
    Question: {question}
    Context: {context}
    
    Provide a detailed and context-aware response that:
    1. Addresses the specific question
    2. Relates to the book's themes and content
    3. Includes relevant examples from the text
    4. if asked about synonyms give 5-7 synonyms generally.
    5. if asked about translation give the translation.
    6. if asked about cultural reference give the historical context, cultural significance and relevance to the book's themes

    """
    response = model.generate_content(prompt)
    answer = ""
    for candidate in response.candidates:
        if candidate.content:
            for part in candidate.content.parts:
                if part.text:
                    answer += part.text
                    break
    return answer

def get_context(text, content):
    words = content.split()
    try:
        index = words.index(text)
        start = max(0, index - 50)
        end = min(len(words), index + 50)
        return ' '.join(words[start:end])
    except ValueError:
        return content[:500]

def detect_language(content):
    if 'the' in content.lower() and 'and' in content.lower():
        return 'English'
    if 'le' in content.lower() and 'la' in content.lower():
        return 'French'
    if 'der' in content.lower() and 'die' in content.lower():
        return 'German'
    return 'English'
        
def extract_text_from_pdf(file_path):
    try:
        print(f"Attempting to extract text from: {file_path}")
        
        # Check if file exists and is accessible
        if not os.path.exists(file_path):
            print(f"File not found at {file_path}")
            return ""
        
        # Normalize the path
        file_path = os.path.abspath(file_path)
        
        # Try different methods to extract text
        try:
            # Method 1: Using pdfplumber
            text = ""
            with pdfplumber.open(file_path) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
            
            if text.strip():
                print(f"Extracted text from PDF: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with pdfplumber: {str(e)}")
        
        try:
            # Method 2: Using PyPDF2
            from PyPDF2 import PdfReader
            reader = PdfReader(file_path)
            text = ""
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            
            if text.strip():
                print(f"Extracted text from PyPDF2: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with PyPDF2: {str(e)}")
        
        try:
            # Method 3: Using pdf2text
            from pdf2text import extract_text
            text = extract_text(file_path)
            if text.strip():
                print(f"Extracted text from pdf2text: {len(text)} characters")
                return text
        except Exception as e:
            print(f"Error with pdf2text: {str(e)}")
        
        print("No content extracted from PDF using any method")
        return ""
    
    except Exception as e:
        print(f"Error extracting text from PDF: {str(e)}")
        return ""
        
@main_bp.route('/get_book_path/<book_id>')
def get_book_path(book_id):
    book = Book.query.get_or_404(book_id)
    
    # Get the correct absolute path
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if not upload_folder.endswith(os.sep):
        upload_folder += os.sep
    
    # Remove 'uploads/' prefix if it exists
    file_path = book.file_path.replace('uploads/', '', 1)
    
    # Construct the full path
    local_path = os.path.join(upload_folder, file_path)
    
    # Check if file exists
    if not os.path.exists(local_path):
        return jsonify({'error': f'File not found at {local_path}'}), 404
    
    return jsonify({
        'local_path': local_path
    })

@main_bp.route('/api/word-lookup', methods=['POST'])
def record_word_lookup():
    data = request.json
    word = data.get('word')
    user_id = current_user.id
    
    lookup = WordLookup.query.filter_by(user_id=user_id, word=word).first()
    if lookup:
        lookup.count += 1
    else:
        lookup = WordLookup(user_id=user_id, word=word, count=1)
        db.session.add(lookup)
    
    db.session.commit()
    return jsonify({'status': 'success'})

@main_bp.route('/api/most-looked-up-words', methods=['GET'])
def get_most_looked_up_words():
    try:
        user_id = current_user.id
        words = WordLookup.query.filter_by(user_id=user_id) \
            .order_by(WordLookup.count.desc()) \
            .limit(10) \
            .all()
        
        result = [{
            'word': word.word,
            'count': word.count
        } for word in words]
        
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_most_looked_up_words: {str(e)}")
        return jsonify({'error': str(e)}), 500

@main_bp.route('/book/<int:book_id>/bookmark', methods=['POST'])
@login_required
def add_bookmark(book_id):
    data = request.json
    page_number = data.get('page_number')
    
    if not page_number:
        return jsonify({'error': 'Page number is required'}), 400
    
    bookmark = Bookmark(
        user_id=current_user.id,
        book_id=book_id,
        page_number=page_number
    )
    db.session.add(bookmark)
    db.session.commit()
    
    response = make_response(jsonify({'message': 'Bookmark added successfully'}))
    response.headers['X-CSRFToken'] = current_app.config['SECRET_KEY']
    return response

@main_bp.route('/book/<int:book_id>/bookmark', methods=['GET'])
@login_required
def get_bookmark(book_id):
    bookmark = Bookmark.query.filter_by(
        user_id=current_user.id,
        book_id=book_id
    ).order_by(Bookmark.timestamp.desc()).first()
    
    if bookmark:
        return jsonify({
            'page_number': bookmark.page_number,
            'timestamp': bookmark.timestamp.isoformat()
        })
    return jsonify({'message': 'No bookmark found'})

@main_bp.route('/api/most-looked-up-words', methods=['GET'])
def get_user_word_lookups():
    try:
        user_id = current_user.id
        words = WordLookup.query.filter_by(user_id=user_id) \
            .order_by(WordLookup.count.desc()) \
            .limit(10) \
            .all()
        
        result = [{
            'word': word.word,
            'count': word.count
        } for word in words]
        
        return jsonify(result)
    except Exception as e:
        print(f"Error in get_most_looked_up_words: {str(e)}")
        return jsonify({'error': str(e)}), 500

# PWA Routes
@main_bp.route('/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json')

@main_bp.route('/sw.js')
def service_worker():
    return send_from_directory('static', 'sw.js')

@main_bp.route('/api/save-progress', methods=['POST'])
def save_progress():
    data = request.json
    # Save progress to database
    return jsonify({'status': 'success'})

@main_bp.route('/api/sync-progress', methods=['POST'])
def sync_progress():
    # Sync progress with server
    return jsonify({'status': 'success'})


@main_bp.route('/offline.html')
def offline():
    return render_template('offline.html')

@main_bp.route('/api/save-offline-messages', methods=['POST'])
def save_offline_messages():
    data = request.json
    messages = data.get('messages', [])
    
    try:
        # Save messages to your database
        for message in messages:
            # Implement your database save logic here
            pass
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@main_bp.route('/api/get-offline-messages', methods=['GET'])
def get_offline_messages():
    try:
        # Get messages from your database
        messages = []
        # Implement your database query here
        return jsonify({'messages': messages})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Initialize the book analyzer
book_path = os.path.join(os.path.dirname(__file__), 'static', 'books', 'your_book.txt')
book_analyzer = BookAnalyzer(book_path)

@main_bp.route('/get_ai_response', methods=['POST'])
def get_ai_response():
    try:
        data = request.json
        if not data:
            return jsonify({
                'error': 'No data received',
                'message': 'Please provide a question and book_id'
            }), 400
        
        question = data.get('question', '')
        book_id = data.get('book_id', 1)
        
        if not question:
            return jsonify({
                'error': 'No question provided',
                'message': 'Please provide a question'
            }), 400
        
        # Get the book path
        upload_folder = os.path.join(current_app.root_path, 'static', 'uploads')
        book_path = os.path.join(upload_folder, 'books', f'book_{book_id}.pdf')
        
        if not os.path.exists(book_path):
            return jsonify({
                'error': 'Book not found',
                'message': f'Book with ID {book_id} not found'
            }), 404
        
        # Create or get existing BookAnalyzer instance
        if 'book_analyzer' not in g:
            g.book_analyzer = BookAnalyzer(book_path)
        
        analyzer = g.book_analyzer
        
        # Handle different types of queries
        if question.startswith("Define:"):
            word = question.replace("Define:", "").strip()
            response = analyzer.get_definition(word)
        elif question.startswith("Synonyms:"):
            word = question.replace("Synonyms:", "").strip()
            response = analyzer.get_synonyms(word)
        elif question.startswith("Explain:"):
            word = question.replace("Explain:", "").strip()
            response = analyzer.get_explanation(word)
        elif question.startswith("Cultural:"):
            word = question.replace("Cultural:", "").strip()
            response = analyzer.get_cultural_context(word)
        else:
            response = analyzer.answer_question(question)
            
        return jsonify({'response': response})
            
    except Exception as e:
        print(f"Error in get_ai_response: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'Failed to process your request. Please try again.',
            'details': str(e)
        }), 500
    
# In routes.py
@main_bp.route('/badges')
@login_required
def badges_page():
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.timestamp.desc()).all()
    notification_count = len(notifications)

    username = current_user.username
    user_initial = username[0].upper() if username else ""
    return render_template('badges.html',
    username=current_user.username,
    user_initial=user_initial,
    notification_count=notification_count,
    notifications=notifications)

@main_bp.route('/api/badges')
@login_required
def get_badges():
    try:
        # Get all available badges
        all_badges = Badge.query.all()
        
        # Get user's earned badges
        user_badges = {ub.badge_id: ub for ub in UserBadge.query.filter_by(user_id=current_user.id).all()}
        
        # Prepare response
        badges_data = []
        for badge in all_badges:
            user_badge = user_badges.get(badge.id)
            badges_data.append({
                'id': badge.id,
                'name': badge.name,
                'description': badge.description,
                'earned': badge.id in user_badges,
                'earned_at': user_badge.earned_at.isoformat() if user_badge else None
            })
            
        return jsonify(badges_data)
    except Exception as e:
        print(f"Error fetching badges: {str(e)}")
        return jsonify({'error': 'Failed to fetch badges'}), 500

@main_bp.route('/api/missions')
@login_required
def get_missions():
    try:
        # Get or create user stats
        stats = UserStats.query.filter_by(user_id=current_user.id).first()
        if not stats:
            stats = UserStats(user_id=current_user.id)
            db.session.add(stats)
            db.session.commit()
        
        # Get all missions
        missions = []
        for key, mission in BADGE_MISSIONS.items():
            try:
                completed = mission['condition'](stats)
                badge = Badge.query.filter_by(name=mission['name']).first()
                icon = badge.icon if badge else 'medal'
                
                missions.append({
                    'id': key,
                    'name': mission['name'],
                    'description': mission['description'],
                    'points': mission.get('points', 10),  # Default to 10 points if not specified
                    'completed': completed,
                    'progress': 1.0 if completed else 0.0,
                    'icon': icon
                })
            except Exception as e:
                print(f"Error processing mission {key}: {str(e)}")
                continue
                
        return jsonify(missions)
        
    except Exception as e:
        print(f"Error in get_missions: {str(e)}")
        return jsonify({'error': str(e)}), 500