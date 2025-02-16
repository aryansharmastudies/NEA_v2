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
import random
import string
########## NOTES ################################
# NOTE: session stores: server_name, user, email, (not password!),
########## IP ADDRESS ###########################
# NOTE - gets the ip. hash the one you don't want.
system = input('windows(w) or linux(l)?')
if system == 'w':
    ip = w_wlan_ip()
else:
    ip = l_wlan_ip()
########## LOGGING ##############################
def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="basic.log",)
########## FLASK ################################
app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(days=30) # session will last for 30 days.
########## DATA BASE ############################
db = SQLAlchemy(app)

class servers(db.Model):
    name = db.Column(db.String(100), primary_key=True)

    def __init__(self, name):
        self.name = name
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
            json_data = json.dumps({'action': 'ping', 'ip_addr':ip})
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
            flash(f'Already Connected with {session['server_name']}!', 'info')
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
        json_data = json.dumps({'action': 'login','l_user':user, 'hash':hash}) # convertes dictionary to json string.
        logging.info(f'hashed password: {hash}')
        logging.info(f'json_data: {json_data}')         
        
        status, status_msg = send(json_data)
        if status == '200':
            session['hash']=hash
            session['user']=user
            flash(f'{status}: {status_msg}', 'info')
            return redirect(url_for('dashboard')) # nm is the dictionary key for name of user input.
        elif status == '401':
            flash(f'{status}: {status_msg}', 'error')
            logging.info(f'401: Unauthorized - Wrong Password - redirecting to login!')
            return redirect(url_for('login'))
        elif status == '404':
            flash(f'{status}: {status_msg}', 'error')
            logging.info(f'404: User does not exist redirecting to login!')
            return redirect(url_for('login'))
        elif status == '503':
            flash(f'{status}: {status_msg}', 'error')
            logging.info(f'503: server offline, please try again')
            return redirect(url_for('login'))
        
    else: # BUG: if the user connects to different server, but has 'user' in sessions, then it will redirect to dashboard !!!
        if 'user' in session and 'server_name' in session: # if user is already logged in, then redirect to user page.
            flash(f'Already Logged In {session['user']}!', 'info')
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

        json_data = json.dumps({'action': 'register_user', 'ip_addr':ip, 'r_user':user, 'hash':hash})
        logging.info(f'hashed password: {hash}')
        logging.info(f'json_data: {json_data}')

        status, status_msg = send(json_data)
        if status == '201':
            flash(f'{status_msg}!', 'info')
            session['hash']=hash # adds hash into session
            session['user']=user
            logging.info(f'user registered: {user}')
            return redirect(url_for('dashboard'))
        elif status == '409':
            flash(f'{status}: {status_msg}', 'error')
            return redirect(url_for('register'))
        elif status == '503':
            flash(f'{status}: {status_msg}', 'error')
            return redirect(url_for('register'))
    else:
        if 'user' in session and 'server_name' in session:
            logging.info(f'Already Logged In {session['user']} in Server {session['server_name']}!')
            flash('Already Logged In!', 'info')
            return redirect(url_for('dashboard'))
        elif 'server_name' not in session:
            flash('You are not connected to a server!', 'info')
            return redirect(url_for('pair'))
        return render_template('register.html')

@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    if request.method == 'POST':
        action = request.form.get('action')
        if not action:
            return jsonify({"error": "Action type not provided"}), 400

        if action == 'add_device':
            username = session['user']
            device_name = request.form.get('device_name').replace(" ", "_")
            mac_addr = get_mac()
            json_data = json.dumps({'action': 'add_device','user':username ,'r_dev_name':device_name, 'mac_addr':mac_addr})
            status, status_msg = send(json_data)
            if status == '201':
                flash(f"{status}: {status_msg} Device '{device_name}' added successfully!", 'info')
                return redirect(url_for('dashboard')) # render_template('dashboard.html', server_name=session['server_name'])
            elif status == '409':
                flash(f"{status}: {status_msg}", 'error')
                return redirect(url_for('dashboard'))
            elif status == '503':
                flash(f"{status}: {status_msg}", 'error')
                return redirect(url_for('dashboard'))        
        
        elif action == 'add_folder':
            folder_label = request.form.get('folder_label')
            folder_id = request.form.get('folder_id')
            folder_path = request.form.get('folder_path')
            folder_type = request.form.get('folder_type')

            json_data = json.dumps({'action': 'add_folder', 'folder_label': folder_label, 'folder_id': folder_id, 'folder_path': folder_path, 'folder_type': folder_type})
            status, status_msg = send(json_data)
            if status == '201':
                flash(f"{status}: {status_msg}", 'info')
                return redirect(url_for('dashboard'))
            elif status == '409':
                flash(f"{status}: {status_msg}", 'error')
                return redirect(url_for('dashboard'))
            elif status == '503':
                flash(f"{status}: {status_msg}", 'error')
                return redirect(url_for('dashboard'))
            return jsonify({'message': f"Folder '{folder_label}' added!"})

        elif action == "join_group":
            group_name = request.form.get('group_name')
            # Perform logic to join a group
            return jsonify({"message": f"Joined group '{group_name}' successfully!"})

        else:
            return jsonify({"error": "Unknown action type"}), 400

    elif 'server_name' in session and 'user' in session:
        random_folder_id = get_random_id()
        return render_template('dashboard.html', server_name=session['server_name'], user=session['user'], random_folder_id=random_folder_id) # pass in server_name to the dashboard.html file.
    elif 'server_name' in session:
        flash('You are not logged in!', 'info')
        return render_template('login.html')
    else:    
        flash('You are not connected to a server!', 'info')
        return render_template('pair.html')

@app.route("/get_users_and_devices", methods=["GET"])
def get_users_and_devices():
    json_data = json.dumps({'action': 'request', 'data': {'users': ['user_id', 'name'], 'devices': ['user_id', 'name']}})
    logging.info(f'getting users and devices info... sending: {json_data}')
    status, status_msg, data = send(json_data)
    return jsonify(data)

@app.route("/unpair")
def unpair():
    if "server_name" in session:
        server_name = session["server_name"]
        flash(f"{server_name} has been unpaired!", "info")
        session.pop("server_name", None)
        return redirect(url_for('pair'))
    else:
        flash("You are not connected to a server!", "info")
        return redirect(url_for('pair'))
    
@app.route('/logout')
def logout():
    if 'user' in session:
        user = session['user']
        flash(f'You have been logged out, {user}', 'info')
    session.pop('user', None)
    session.pop('hash', None) # SECURITY: to ensure hash removed from session incase someone tries to access it.
    logging.info(f'{session}')
    return redirect(url_for('login'))

########## SEND #################################
def send(json_data):
        try: 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((session['server_name'], 8000))
        except: 
            logging.info(f'503 Server Offline')
            return '503', 'server offline'   
        s.send(json_data.encode('utf-8')) # sending data to server 📨
        json_response = s.recv(1024).decode('utf-8') # server's response back 📩 # TODO recieves 1024 bits, add buffering feature !!
        logging.info(f'JSON_RESPONSE: {json_response}')
        server_data = json.loads(json_response)
        status = server_data.get('status', '200')
        status_msg = server_data.get('status_msg', 'unknown')
        data = server_data.get('data', False) # incase 'data' key don't exist, simply set data = False
    
        logging.info(f'json_data sent: {json_data}')
        logging.info(f'server response: {json_response}')
        if status == '200': # The request is OK (this is the standard response for successful HTTP requests)
            logging.info(f"200 OK")
            if not data: # if there is NO DATA incomming (which means, we as the client DIDNT request for data
                # e.g. adding a user), simply return the status and status_msg!
                return status, status_msg
            else: # but if data is recieved, if we as the client made a request.
                return status, status_msg, data # return the data.
        elif status == '201': # The request has been fulfilled, and a new resource(user/device/...) is created
            logging.info(f"201 Added")
            return status, status_msg
        elif status == '401':
            logging.info(f'401 Unauthorized') #  The request was a legal request, but the server is refusing to respond to it. For use when authentication is possible but has failed or not yet been provided
            return status, status_msg
        elif status == '404':
            logging.info(f'404 Not Found') # The requested page/item could not be found but may be available again in the future
            return status, status_msg
        elif status == '409':
            logging.info(f'409 Conflict') # The request could not be completed because of a conflict in the request
            return status, status_msg
        
        else:
            return '500', 'server error - check return status for CRUD!' 
       
########## ADDING USER ##########################
# NOTE could use this function rather then coding add_user in the login and register functions.
def add_user(name, email):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('osaka', 8000))
    s.send(f"{name}:{email}".encode('utf-8'))

def get_random_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

########## MAIN #################################
if __name__ == "__main__":
    main()
    with app.app_context():
        db.create_all()
    app.run(debug=True)