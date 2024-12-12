from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import timedelta # setup max time out session last for.
from flask_sqlalchemy import SQLAlchemy
from uuid import getnode as get_mac


app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(minutes=5) # session will 

db = SQLAlchemy(app)

class users(db.Model): # inherits from db.Model
    user_id = db.Column("user_id", db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))

    def __init__(self, name, email):
        self.name = name
        self.email = email

class devices(db.Model):
    user_id = db.Column("user_id", db.Integer)
    name = db.Column(db.String(100))
    mac_addr = db.Column(db.String(48), primary_key=True)

    def __init__(self, user_id, name, mac_addr): # initializes each device with this.
        self.user_id = user_id
        self.name = name
        self.mac_addr = mac_addr

@app.route("/") # in the url if we type localhost:5000/home we are returned with home page.
def home(): #represents the homecase...
    return render_template("index.html")

@app.route("/dump")
def dump():
    return render_template("dump.html", values=users.query.all())

@app.route("/login", methods=["POST", "GET"]) # in the url if we type localhost:5000/login we are returned with login page.
def login():
    # Handle the form submission
    if request.method == "POST":
        session.permanent = True # session will last for 5 minutes.
        user = request.form["nm"]
        session["user"]=user
        found_user = users.query.filter_by(name=user).first() # 'filters by' name = user and grabs the 'first' entry.
        if found_user:
           session["email"] = found_user.email 
        else:
            user = users(user, None)
            db.session.add(user)
            db.session.commit()

        flash(f"Login Successful!", "info")
        return redirect(url_for("user")) # nm is the dictionary key for name of user input.
    else:
        if "user" in session: # if user is already logged in, then redirect to user page.
            flash("Already Logged!", "info")
            return redirect(url_for("user"))
        
        return render_template("login.html")


@app.route("/user", methods=["POST", "GET"])
def user():
    email = None
    device = None
    mac = get_mac()
    print(mac)

    if "user" in session:
        user = session["user"]
        print("######################################")
        print(user)
        print(user.name)

        if request.method == "POST":
            if len(request.form["email_key"]) != 0:
                email = request.form["email_key"]
            if len(request.form["device_key"]) != 0:
                device = request.form["device_key"]

            session["email"] = email
            session["device"] = device

            found_user = users.query.filter_by(name=user).first()
            found_user.email = email

            device = devices(user.user_id, device, mac)
            db.session.add(device)

            db.session.commit()
            flash("Email was saved!", "info")
        else: # if the request.method is GET
            if "email" in session:
                email = session["email"]

        return render_template("user.html", email=email)
    else:
        flash("You are not logged in!", "info")
        return redirect(url_for("login"))
    

@app.route("/logout")
def logout():
    if "user" in session:
        user = session["user"]
        flash(f"You have been logged out, {user}", "info")
    session.pop("user", None)
    session.pop("email", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)