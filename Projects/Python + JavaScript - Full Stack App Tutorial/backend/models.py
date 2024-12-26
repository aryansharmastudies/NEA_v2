# contains database models and interaction with flasksqlalchemy
from config import db

class Contact(db.Model): # db model represented as a python class.
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), unique=False, nullable=False) # cant make first_name null value
    last_name = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def to_json(self): # javascript object notation- really just looks like python dictionary. passing contacts back and forth to frontend
        return {
            "id": self.id,
            "firstName": self.first_name, # firstName is in camel case. first_name is snake case
            "lastName": self.last_name,
            "email": self.email,
        }