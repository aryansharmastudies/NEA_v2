from flask import Flask, redirect, url_for, render_template, request, session
from datetime import timedelta # setup max time out session last for.

app = Flask(__name__)
app.secret_key = "hello"
app.permanent_session_lifetime = timedelta(minutes=5) # session will 

@app.route("/") # in the url if we type localhost:5000/home we are returned with home page.
def home(): #represents the homecase...
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"]) # in the url if we type localhost:5000/login we are returned with login page.
def login():
    # Handle the form submission
    if request.method == "POST":
        session.permanent = True # session will last for 5 minutes.
        user = request.form["nm"]
        session["user"]=user
        return redirect(url_for("user")) # nm is the dictionary key for name of user input.
    else:
        if "user" in session: # if user is already logged in, then redirect to user page.
            return redirect(url_for("user"))
        
        return render_template("login.html")

@app.route("/user")
def user():
    if "user" in session:
        user = session["user"]
        return f"<h1>{user}</h1>"
    else:
        return redirect(url_for("login"))
    
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)