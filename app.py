from flask import Flask
from config import ProductionConfig
import os

app = Flask(__name__)
app.config.from_object(ProductionConfig)

if __name__ == '__main__':
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    ) 