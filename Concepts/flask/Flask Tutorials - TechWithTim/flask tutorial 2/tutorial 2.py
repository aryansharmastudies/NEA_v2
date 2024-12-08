from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)

@app.route("/<name>/<subject>") # in the url if we type localhost:5000/home we are returned with home page.
def home(name, subject): #represents the homecase...
    return render_template("index.html", subject=subject, content=name, names=["hazique", "ailie", "riadoor"])

if __name__ == "__main__":
    app.run() 