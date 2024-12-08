from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)

@app.route("/") # in the url if we type localhost:5000/home we are returned with home page.
def home(): #represents the homecase...
    return render_template("index.html")

@app.route("/admin")
def admin():
    return render_template("admin.html")

if __name__ == "__main__":
    app.run(debug=True)