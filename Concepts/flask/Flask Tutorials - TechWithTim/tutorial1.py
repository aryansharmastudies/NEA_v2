from flask import Flask, redirect, url_for

app = Flask(__name__)

@app.route("/") # in the url if we type localhost:5000/home we are returned with home page.
def home(): #represents the homecase...
    return "Hello <h1>Aryan!<h1>"

@app.route("/<name>") #<name> will be passed into the function.
def user(name):
    return f"hello {name}"

@app.route("/admin/")
def admin():
    return redirect(url_for("user", name="Admin!")) #redirects admin to home. just for fun. =)

if __name__ == "__main__":
    app.run()