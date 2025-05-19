from flask import Flask
from config import ProductionConfig
from app import create_app

app = create_app(ProductionConfig)

# Always run the app with these settings
app.run(
    host='0.0.0.0',  # Force it to listen on all public interfaces
    port=5000,
    debug=False
) 