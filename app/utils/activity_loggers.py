from datetime import datetime
from flask import current_app
from app import db
from app.models import UserActivity

def log_activity(user_id, activity_type, request, details=None):
    """
    Log user activity to the database
    
    Args:
        user_id: ID of the user performing the activity
        activity_type: Type of activity (e.g., 'login', 'logout', 'upload')
        request: Flask request object
        details: Additional details about the activity (optional)
    """
    try:
        activity = UserActivity(
            user_id=user_id,
            activity_type=activity_type,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None,
            details=details,
            visit_date=datetime.utcnow(),
            timestamp=datetime.utcnow()
        )
        db.session.add(activity)
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error logging activity: {str(e)}")
        return False