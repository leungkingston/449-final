from flask import Flask
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
from datetime import timedelta

app = Flask(__name__)

app.config['MONGO_URI'] = 'mongodb://localhost:27017/restaurant'
mongo = PyMongo(app)


app.config['JWT_SECRET_KEY'] = '1f509c5b57604f6a95d220f396a5ab9d'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'jwt'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)

from views import bp as views_bp
app.register_blueprint(views_bp)

if __name__ == '__main__':
    app.run(debug=True)
