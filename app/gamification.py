# Create a file called gamification.py
from datetime import datetime, timedelta

# In gamification.py
def check_and_award_badges(user):
    """Check user's stats against badge conditions and award badges"""
    stats = UserStats.query.filter_by(user_id=user.id).first()
    if not stats:
        return

    for badge_id, mission in BADGE_MISSIONS.items():
        # Check if user already has this badge
        has_badge = UserBadge.query.filter_by(
            user_id=user.id,
            badge_id=badge_id
        ).first()
        
        if not has_badge and mission['condition'](stats):
            # Award the badge
            user_badge = UserBadge(
                user_id=user.id,
                badge_id=badge_id
            )
            db.session.add(user_badge)
            # Update user points
            user.points = (user.points or 0) + mission['points']
    
    db.session.commit()

def update_streak(user):
    """Update user's reading streak"""
    stats = UserStats.query.filter_by(user_id=user.id).first()
    if not stats:
        stats = UserStats(user_id=user.id)
        db.session.add(stats)
    
    today = datetime.utcnow().date()
    last_activity = stats.last_activity.date() if stats.last_activity else None
    
    if last_activity == today:
        return  # Already updated today
    
    if last_activity == today - timedelta(days=1):
        stats.current_streak += 1
        if stats.current_streak > stats.max_streak:
            stats.max_streak = stats.current_streak
    elif last_activity and last_activity < today - timedelta(days=1):
        stats.current_streak = 1  # Reset streak if broken
    
    stats.last_activity = datetime.utcnow()
    db.session.commit()
    check_and_award_badges(user)

def complete_book(user, book_pages):
    """Handle book completion and update user stats"""
    # Get or create user stats
    stats = UserStats.query.filter_by(user_id=user.id).first()
    if not stats:
        stats = UserStats(user_id=user.id)
        db.session.add(stats)
    
    # Update basic stats
    stats.total_books_read += 1
    stats.total_pages_read += book_pages
    
    # Check if book was read in one day
    # You'll need to track reading sessions to implement this accurately
    # For now, we'll just update the streak
    stats.last_activity = datetime.utcnow()
    
    db.session.commit()
    
    # Update streak and check for badges
    update_streak(user)
    check_and_award_badges(user)

BADGE_MISSIONS = {
    # Reading Milestones
    'first_book': {
        'name': 'First Steps',
        'description': 'Read your first book',
        'points': 10,
        'condition': lambda stats: stats.total_books_read >= 1
    },
    'book_worm': {
        'name': 'Book Worm',
        'description': 'Read 5 books',
        'points': 25,
        'condition': lambda stats: stats.total_books_read >= 5
    },
    'page_turner': {
        'name': 'Page Turner',
        'description': 'Read 100 pages',
        'points': 15,
        'condition': lambda stats: stats.total_pages_read >= 100
    },
    'speed_reader': {
        'name': 'Speed Reader',
        'description': 'Read 500 pages in a week',
        'points': 50,
        'condition': lambda stats: stats.pages_this_week >= 500
    },
    
    # Streak Based
    'early_bird': {
        'name': 'Early Bird',
        'description': 'Read in the morning for 5 days in a row',
        'points': 30,
        'condition': lambda stats: stats.morning_streak >= 5
    },
    'night_owl': {
        'name': 'Night Owl',
        'description': 'Read at night for 5 days in a row',
        'points': 30,
        'condition': lambda stats: stats.night_streak >= 5
    },
    'streak_master': {
        'name': 'Streak Master',
        'description': 'Maintain a 7-day reading streak',
        'points': 50,
        'condition': lambda stats: stats.current_streak >= 7
    },
    
    # Community & Sharing
    'book_clubber': {
        'name': 'Book Clubber',
        'description': 'Join a reading group',
        'points': 15,
        'condition': lambda stats: stats.groups_joined >= 1
    },
    
    # Content Creation
    'note_taker': {
        'name': 'Note Taker',
        'description': 'Create 10 notes across your books',
        'points': 25,
        'condition': lambda stats: stats.notes_created >= 10
    },
    
    # Vocabulary
    'word_nerd': {
        'name': 'Word Nerd',
        'description': 'Look up 20 words in the dictionary',
        'points': 20,
        'condition': lambda stats: stats.words_looked_up >= 20
    },
    
    # Challenges
    'weekend_warrior': {
        'name': 'Weekend Warrior',
        'description': 'Read every day of the weekend',
        'points': 25,
        'condition': lambda stats: stats.weekend_reading_days >= 2
    },
    'marathon_reader': {
        'name': 'Marathon Reader',
        'description': 'Read for 5 hours in a single session',
        'points': 75,
        'condition': lambda stats: stats.longest_session_minutes >= 300
    },
    'completionist': {
        'name': 'Completionist',
        'description': 'Complete all other badges',
        'points': 100,
        'condition': lambda stats: len([b for b in stats.earned_badges if b != 'completionist']) >= 14
    }
}