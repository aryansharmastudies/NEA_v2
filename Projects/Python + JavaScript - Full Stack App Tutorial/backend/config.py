# contains main config of our appliciation
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS # cross origin requests - semd request to this backend from different URL.

app = Flask(__name__)
CORS(app) # now we can send cross origin requests to app.

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///mydatabase.db" # specifing location of local sqlite db we are storing.
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False # not gonna track modifications made to database

db = SQLAlchemy(app)
