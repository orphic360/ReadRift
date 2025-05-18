from app import create_app
from app.models import db, Badge
from app.gamification import BADGE_MISSIONS

app = create_app()

with app.app_context():
    badge_icons = {
        'First Steps': 'book',
        'Book Worm': 'book-reader',
        'Page Turner': 'book-open',
        'Speed Reader': 'bolt',
        'Early Bird': 'sun',
        'Night Owl': 'moon',
        'Streak Master': 'fire',
        'Book Clubber': 'comments',
        'Note Taker': 'sticky-note',
        'Word Nerd': 'spell-check',
        'Weekend Warrior': 'calendar-week',
        'Marathon Reader': 'running',
        'Completionist': 'trophy'
    }

    for name, icon in badge_icons.items():
        badge = Badge.query.filter_by(name=name).first()
        if not badge:
            description = next((m['description'] for m in BADGE_MISSIONS.values() if m['name'] == name), '')
            badge = Badge(name=name, description=description, icon=icon)
            db.session.add(badge)
        else:
            badge.icon = icon
        print(f"Updated badge: {name} with icon: {icon}")

    db.session.commit()
    print("All badges have been updated successfully!")