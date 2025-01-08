from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta # setup max time out session last for.
from flask_sqlalchemy import SQLAlchemy
from uuid import getnode as get_mac
from get_wip import *
from get_lip import *
import logging
import socket
import os
import json
import hashlib
########## NOTES ################################
# NOTE: session stores: server_name, user, email, (not password!),

#################################################
########## IP ADDRESS ###########################
# NOTE - gets the ip. hash the one you don't want.
#ip = l_wlan_ip()
ip = w_wlan_ip()
#################################################
########## FLASK ################################
app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(days=30) # session will last for 30 days.
#################################################
########## DATA BASE ############################
db = SQLAlchemy(app)

class servers(db.Model):
    name = db.Column(db.String(100), primary_key=True)

    def __init__(self, name):
        self.name = name
#################################################
########## WEBSITE ##############################
@app.route('/pair', methods=['POST','GET'])
def pair():
    if request.method == 'POST':
        session.permanent = True
        server_name = request.form['nm'] # nm is dictionary key.
        logging.info(f'server_name: {server_name}')
        try: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_name, 8000))
            json_data = json.dumps({'action': 'ping'})
            logging.info(f'ping sent: {json_data}')
            s.send(json_data.encode('utf-8'))
            if s.recv(1024).decode('utf-8') == 'pong':
                logging.info(f"status: pong")
                session['server_name'] = server_name
                
                found_server = servers.query.filter_by(name=server_name).first()
                logging.info(f'found_server: {found_server}')
                if found_server:
                    flash(f'Reconnected!', 'info')
                    return redirect(url_for('login'))
                else:
                    server = servers(server_name)
                    db.session.add(server)
                    db.session.commit()
                
                flash(f'Connected!', 'info')
                return redirect(url_for('login'))
            else:
                flash(f'Server inactive, please retry!', 'info')
                return redirect(url_for('pair'))
        except: 
            flash(f'Could not connect to server!', 'info')
            return redirect(url_for('pair'))
    else:
        if 'server_name' in session:
            flash('Already Connected!', 'info')
            return redirect(url_for('login'))
        
        return render_template('pair.html')
    
    # DONE: if the user is already connected to a pi and in a session, redirect to dashboard page.
    # DONE: do a GET request and get the hostname to connect to.
    # DONE: then try establish a connection and display it onto the page.
@app.route("/login", methods=['POST', 'GET']) # in the url if we type localhost:5000/login we are returned with login page.
def login():
    # Handle the form submission
    if request.method == 'POST':
        user = request.form['r_user']
        pwd = request.form['r_pwd']
        hash = hashlib.new("SHA256")
        hash.update(pwd.encode('utf-8'))
        hash = hash.hexdigest()
        session['hash']=hash
        session['user']=user
        json_data = json.dumps({'action': 'login','r_user':user, 'hash':hash}) # convertes dictionary to json string.
        logging.info(f'hashed password: {hash}')
        logging.info(f'json_data: {json_data}')        
        try: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((session['server_name'], 8000))
            s.send(json_data.encode('utf-8'))
        except:
            flash(f'Could not connect to server for login!', 'info')
            return redirect(url_for('login'))
        
        flash(f'Login Successful!', 'info')
        return redirect(url_for('dashboard')) # nm is the dictionary key for name of user input.
    else:
        if 'user' in session and 'server_name' in session: # if user is already logged in, then redirect to user page.
            flash('Already Logged In!', 'info')
            return redirect(url_for('dashboard'))
        elif 'server_name' not in session:
            flash('You are not connected to a server!', 'info')
            return redirect(url_for('pair'))   
        return render_template("login.html")
    
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        user = request.form['r_user']
        pwd = request.form['r_pwd']
        hash = hashlib.new("SHA256")
        hash.update(pwd.encode('utf-8'))
        hash = hash.hexdigest()
        session['hash']=hash
        session['user']=user
        json_data = json.dumps({'action': 'add_user','r_user':user, 'hash':hash})
        logging.info(f'hashed password: {hash}')
        logging.info(f'json_data: {json_data}')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((session['server_name'], 8000))
            s.send(json_data.encode('utf-8'))
        except:
            flash(f'Could not connect to server for register!', 'info')
            return redirect(url_for('register'))
        flash(f'Registered!', 'info')
        return redirect(url_for('dashboard'))
    else:
        if 'user' in session and 'server_name' in session:
            flash('Already Logged In!', 'info')
            return redirect(url_for('dashboard'))
        elif 'server_name' not in session:
            flash('You are not connected to a server!', 'info')
            return redirect(url_for('pair'))
        return render_template('register.html')

@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    if 'server_name' in session and 'user' in session:
        return render_template('dashboard.html', server_name=session['server_name']) # pass in server_name to the dashboard.html file.
    elif 'server_name' in session:
        flash('You are not logged in!', 'info')
        return render_template('login.html', server_name=session['server_name'])
    else:    
        flash('You are not connected to a server!', 'info')
        return render_template('pair.html')
@app.route("/unpair")
def unpair():
    if "server_name" in session:
        server_name = session["server_name"]
        flash(f"{server_name} has been unpaired!", "info")
    session.pop("server_name", None)
    return redirect(url_for('pair'))
@app.route('/logout')
def logout():
    if 'user' in session:
        user = session['user']
        flash(f'You have been logged out, {user}', 'info')
    session.pop('user', None)
    #session.pop('email', None)
    return redirect(url_for('login'))
#################################################
########## LOGGING ##############################
def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="basic.log",)
    
#################################################
########## ADDING USER ##########################
def add_user(name, email):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('osaka', 8000))
    s.send(f"{name}:{email}".encode('utf-8'))
#################################################
if __name__ == "__main__":
    main()
    with app.app_context():
        db.create_all()
    app.run(debug=True)