from app import create_app, db
from app.models import User, UserRole
from werkzeug.security import generate_password_hash

def create_admin():
    """Create an admin user with role selection."""
    print("Create a new admin user")
    email = input("Enter admin email: ").strip()
    username = input("Enter admin username: ").strip()
    password = input("Enter admin password: ").strip()
    
    # Show role options
    print("\nSelect admin role:")
    print("1. System Admin")
    print("2. Content Manager")
    role_choice = input("Enter role number (1 or 2): ").strip()
    
    # Map choice to role
    role_map = {
        '1': UserRole.SYSTEM_ADMIN,
        '2': UserRole.CONTENT_MANAGER
    }
    
    if role_choice not in role_map:
        print("Error: Invalid role selection!")
        return

    role = role_map[role_choice]

    app = create_app()

    with app.app_context():
        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print("Error: Email is already registered!")
            return

        # Create a new admin user with the selected role
        hashed_password = generate_password_hash(password)
        admin_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role,
            is_admin=True
        )

        db.session.add(admin_user)
        db.session.commit()
        print(f"Success: {role.value} user '{username}' created successfully!")

if __name__ == "__main__":
    create_admin()