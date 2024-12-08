from flask import Flask, redirect, url_for, render_template, request

app = Flask(__name__)

@app.route("/") # in the url if we type localhost:5000/home we are returned with home page.
def home(): #represents the homecase...
    return render_template("index.html")

@app.route("/login", methods=["POST", "GET"]) # in the url if we type localhost:5000/login we are returned with login page.
def login():
    if request.method == "POST":
        user = request.form["nm"]
        return redirect(url_for("user", usr=user)) # nm is the dictionary key for name of user input.
    else:
        return render_template("login.html")

@app.route("/<usr>")
def user(usr):
    return f"<h1>{usr}</h1>"

if __name__ == "__main__":
    app.run(debug=True)