from app import create_app, db, socketio

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures the database tables are created
    socketio.run(app, host='0.0.0.0', port=80, debug=True)
