from flask import Flask
from config import ProductionConfig
import os

app = Flask(__name__)
app.config.from_object(ProductionConfig)

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',  # Force it to listen on all public interfaces
        port=5000,
        debug=False
    ) 