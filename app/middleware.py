from datetime import datetime
from flask import request, current_app
from flask_login import current_user
from . import db
from .models import UserActivity

def track_user_activity():
    if request.endpoint and request.endpoint != 'static' and current_user.is_authenticated:
        try:
            current_week = datetime.utcnow().isocalendar()[1]
            
            # Get the last activity record for this user in current week
            last_activity = UserActivity.query.filter_by(
                user_id=current_user.id,
                week_number=current_week
            ).order_by(UserActivity.visit_date.desc()).first()
            
            if last_activity:
                # Calculate time difference in minutes
                time_diff = (datetime.utcnow() - last_activity.visit_date).total_seconds() / 60
                
                if time_diff > 30:  # 30 minutes threshold for new session
                    # Create a new activity record for new session
                    activity = UserActivity(
                        user_id=current_user.id,
                        activity_type='page_view',  # Add activity type
                        duration_minutes=0,
                        week_number=current_week,
                        visit_date=datetime.utcnow(),  # Add visit date
                        timestamp=datetime.utcnow()    # Add timestamp
                    )
                    db.session.add(activity)
                    db.session.commit()
                # Update duration if more than 1 minute has passed
                elif time_diff > 1:
                    last_activity.duration_minutes += int(time_diff)
                    last_activity.last_update = datetime.utcnow()  # Update last update time
                    db.session.commit()
            else:
                # Create new activity record if none exists for this week
                activity = UserActivity(
                    user_id=current_user.id,
                    activity_type='page_view',  # Add activity type
                    duration_minutes=0,
                    week_number=current_week,
                    visit_date=datetime.utcnow(),  # Add visit date
                    timestamp=datetime.utcnow()    # Add timestamp
                )
                db.session.add(activity)
                db.session.commit()
        except Exception as e:
            current_app.logger.error(f"Error in activity tracking: {str(e)}")
            db.session.rollback()