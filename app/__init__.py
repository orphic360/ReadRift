import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from datetime import datetime, timedelta
from config import Config
from flask_socketio import SocketIO, join_room


socketio = SocketIO()
db = SQLAlchemy()
login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from .models import User  # Import here to avoid circular import
    return User.query.get(int(user_id))

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
 

    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
    books_dir = os.path.join(upload_dir, 'books')
    covers_dir = os.path.join(upload_dir, 'covers')
    
    # Create directories if they don't exist
    os.makedirs(books_dir, exist_ok=True)
    os.makedirs(covers_dir, exist_ok=True)
    
    app.config['UPLOAD_FOLDER'] = upload_dir

    socketio.init_app(app)    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    

    with app.app_context():
        # Import models here to avoid circular import
        from . import models
        db.create_all()

    from .routes import main_bp
    app.register_blueprint(main_bp)

     # Register middleware
    from .middleware import track_user_activity
    app.before_request(track_user_activity)
    
    @app.before_request
    def update_user_activity():
        if current_user.is_authenticated:
            today = datetime.utcnow().date()
            if not hasattr(current_user, 'last_seen') or current_user.last_seen.date() != today:
                current_user.last_seen = datetime.utcnow()
                db.session.commit()

    return app
@socketio.on('join')
def on_join(data):
    group_id = data['group_id']
    join_room(f"group_{group_id}")

