from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from werkzeug.serving import run_simple
from datetime import timedelta # setup max time out session last for.
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_socketio import send, emit
from flask_socketio import join_room, leave_room
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
import threading
########## NOTES ################################
# NOTE: session stores: server_name, user, email, (not password!),
########## IP ADDRESS ###########################
# NOTE - gets the ip. hash the one you don't want.

########## LOGGING ##############################
def log() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="basic.log",)
########## FLASK ################################
app = Flask(__name__)
app.secret_key = "shady"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(days=30) # session will last for 30 days.
########## DATA BASE ############################
db = SQLAlchemy(app)

class servers(db.Model):
    name = db.Column(db.String(100), primary_key=True)

    def __init__(self, name):
        self.name = name

########## WEB SOCKETS ##########################
socketio = SocketIO(app)

# NOTE: alerts will be in the form [['folder_label','id','host'],[...],[...]]

# @socketio.on('echo_alerts')
# def echo_alerts(alerts):
#     emit('alerts', alerts) # ❓

# def echo_alerts_v2(alerts):
#     socketio.emit('alerts', alerts) # ❓

# @socketio.on('change message')
# def change_message(json):
#     print('recieved json: ' + str(json))
#     emit('message', json, broadcast=True)

# @socketio.on('my event')
# def handle_my_custom_event(json):
#     print('received json: ' + str(json))

@socketio.on('connect')
def handle_connect():
    logging.info(f'connected to frontend!')
    socketio.emit('alerts', session['alerts']) # ⭐
    logging.info(f'sending alerts to frontend!: {session["alerts"]}')
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
            s.send(json_data.encode('utf-8'))       # TODO MAYBE USE SEND FUNCTION TO GENERALISE EVERYTHING?
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

            active_session['user'] = user # global dictionary of session that can be passed to threads

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
            active_session['user'] = user # global dictionary of session that can be passed to threads
            logging.info(f'user registered: {user}')
            return redirect(url_for('dashboard'))
        elif status == '409':
            flash(f'{status}: {status_msg}', 'error')
            return redirect(url_for('register'))
        elif status == '503':
            flash(f'{status}: {status_msg}', 'error')
            return redirect(url_for('register'))
    else: # BUG - if user in session, it auto redirects to dashboard.(even if user is not logged in)
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

    elif 'server_name' in session and 'user' in session: # if used logs in/registers,

        mac_addr = get_mac()
        ip_tracking_data = json.dumps({'action': 'track', 'ip_addr':ip, 'user':session['user'], 'mac_addr':mac_addr}) # dont matter if user's registerd device.
        logging.info(f'tracking_data sent: {ip_tracking_data}')
        status, status_msg, data = send(ip_tracking_data)        
        session['alerts'] = data
        logging.info(f'storing alerts to sessions!: {data}')

        # socketio.emit('alerts', data) #⭐
        # echo_alerts(data) #⭐
        # socketio.emit('message', 'new notification!!!', broadcast=True)
        # change_message('new notification!!!')

        random_folder_id = get_random_id()

        # TODO - get any notifications from the server.
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
    data = send(json_data)

    devices = data['devices']
    users = data['users']

    id_to_users = {}
    users_and_device = {}
    
    for user in users:
        id_to_users[user[0]] = user[1]
        users_and_device[user[1]] = []

    for device in devices:
        username = id_to_users[device[0]]
        users_and_device[username].append(device[1])
    
    logging.info(f'Sending to frontend: {users_and_device}')

    return jsonify(users_and_device)

@app.route("/unpair")
def unpair():
    if "user" in session:
        user = session["user"]
        flash(f"{user} has been logged out!", "info")
        session.pop("user", None)
        active_session.pop('user', None)

    if "hash" in session:
        session.pop("hash", None)

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
    active_session.pop('user', None)
    session.pop('hash', None) # SECURITY: to ensure hash removed from session incase someone tries to access it.
    logging.info(f'{session}')
    return redirect(url_for('login'))

# 😳
@app.route("/submit_folder", methods=["POST"])
def submit_folder():
    # Get the JSON data from the request
    data = request.get_json()
    mac_addr = get_mac()
    data['mac_addr'] = mac_addr
    logging.info(f'DATA FROM ADDING FOLDER FORMS!: {data}')

    data = json.dumps(data)
    status, status_msg = send(data)
    logging.info(f'submit_folder status: {status}')
    if status == '201':
    # Return a response
        return jsonify({'status': 'success', 'message': 'Folder added successfully'})
    else: 
        return jsonify({'status': 'failure', 'message': 'Folder not added, please try again'})
# 😳

########## SEND #################################
def send(json_data): # 🛫
        logging.info(f'sending data to server: {json_data}')
        try: 
            logging.info(f'trying to connect to server: {session["server_name"]} on port 8000')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((session['server_name'], 8000))
        except: 
            logging.info(f'503 Server Offline')
            flash(f'Server inactive, please retry!', 'info')
            
            action = json.loads(json_data)['action']
            if action in ['login', 'register_user', 'add_device', 'add_folder']:
                return '503', 'server offline'
            elif action in ['track']:
                return '503', 'server offline', False
            elif action in ['request']:
                return False
            
        s.send(json_data.encode('utf-8')) # sending data to server 📨
        json_response = s.recv(1024).decode('utf-8') # server's response back 📩 # TODO recieves 1024 bits, add buffering feature !!
        logging.info(f'server response: {json_response}, type: {type(json_response)}')
        
        server_data = json.loads(json_response)
        logging.info(f'server_data: {server_data}')
        
        status = server_data.get('status', '200')
        logging.info(f'status: {status}')
        
        status_msg = server_data.get('status_msg', 'unknown')
        logging.info(f'status_msg: {status_msg}')
        
        data = server_data.get('data', False) # incase 'data' key don't exist, simply set data = False
        logging.info(f'data: {data}')
        
        logging.info(f'status: {status} status_msg: {status_msg} data: {data}')
        
        # could use hashmap i.e. {200: 'ok', 201: 'created', 401: 'unauthorized'} then returns in O(1) time.
        status_to_codes = {'200': 'OK', '201': 'Added', '401': 'Unauthorized', '404': 'Not Found', '409': 'Conflict'}
        logging.info(f'{status} : {status_to_codes[status]}')
        
        # if status == '200': # The request is OK (this is the standard response for successful HTTP requests)
        #     logging.info(f"200 OK")
        #     if data: # but if data is recieved, if we as the client made a request. 
        #         # e.g. adding a user), simply return the status and status_msg!
        #         return status, status_msg, data
        #     else: # if there is NO DATA incomming (which means, we as the client DIDNT request for data
        #         return status, status_msg # return the data.
        # elif status == '201': # The request has been fulfilled, and a new resource(user/device/...) is created
        #     logging.info(f"201 Added")
        #     return status, status_msg
        # elif status == '401':
        #     logging.info(f'401 Unauthorized') #  The request was a legal request, but the server is refusing to respond to it. For use when authentication is possible but has failed or not yet been provided
        #     return status, status_msg
        # elif status == '404':
        #     logging.info(f'404 Not Found') # The requested page/item could not be found but may be available again in the future
        #     return status, status_msg
        # elif status == '409':
        #     logging.info(f'409 Conflict') # The request could not be completed because of a conflict in the request
        #     return status, status_msg
        
        # else:
        #     return '500', 'server error - check return status for CRUD!' 
        action = json.loads(json_data)['action']
        if action in ['login', 'register_user', 'add_device', 'add_folder']:
            return status, status_msg
        elif action in ['track']:
            return status, status_msg, data
        elif action in ['request']:
            return data
            



########## HANDLE SERVER MESSAGE ################

def handle_server_message(json_message, server_socket):
    if json_message['action'] == 'authorise':
        logging.info(f'authorisation recieved: {json_message}')
        if active_session['user'] == json_message['user']:

            # try request.session['user']
            message = json.dumps({'status_code': '200'})
            server_socket.send(message.encode('utf-8'))
        else:
            message = json.dumps({'status_code': '404'})
            server_socket.send(message.encode('utf-8'))
    elif json_message['action'] == 'share_folder':
        # need to create a popup on dashboard to accept or decline the folder.
        logging.info(f'sharing folder: {json_message}')
        # TODO toggle the modal to popup.
        random_folder_id = get_random_id()
        return render_template('dashboard.html', server_name=session['server_name'], user=session['user'], random_folder_id=random_folder_id, share_folder=json_message)
        # continue with the rest of code.


def listen_for_messages():
    # Create a socket to listen for incoming messages
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    logging.info(f"binding to ip: {ip}")
    s.bind((ip, 6000))  # Listen on all available interfaces, port 6000
    s.listen(5)  # Allow up to 5 connections

    logging.info("Listening for incoming messages on port 6000...")

    while True:
        server_socket, addr = s.accept()
        logging.info(f"Connection from {addr} established.")
        message = server_socket.recv(1024).decode('utf-8')
        logging.info(f"Message received: {message}")
        
        # Pass the message to the handle_server_message function
        try:
            json_message = json.loads(message)
            handle_server_message(json_message, server_socket)
        except json.JSONDecodeError:
            logging.error("Received message is not valid JSON.")
        
        server_socket.close()

########## ADDING USER ##########################
# NOTE could use this function rather then coding add_user in the login and register functions.
# def add_user(name, email):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect(('osaka', 8000))
#     s.send(f"{name}:{email}".encode('utf-8'))

def get_random_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))


########## MAIN #################################
def run_flask():
    """Function to run the Flask server using run_simple."""
    print("Running Flask server...")
    run_simple("0.0.0.0", 1234, app, use_reloader=False)

def run_socketio():
    """Function to run the Flask-SocketIO server."""
    print("Running SocketIO server...")
    socketio.run(app)


if __name__ == "__main__":
    log()  # Start the logging system
    active_session = {}

    system = input("windows(w) or linux(l)? ")
    ip = w_wlan_ip() if system == "w" else l_wlan_ip()

    print(f"Binding IP: {ip}")

    # Start the listener thread for message listening
    listener_thread = threading.Thread(target=listen_for_messages, daemon=True)
    # daemon=True ensures thread exits when main program exits!!
    listener_thread.start()

    # Set up the Flask app with database
    with app.test_request_context("/"):
        request.session = session
        db.create_all()

    # Start the Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # socketio_thread = threading.Thread(target=run_socketio, daemon=True)
    # socketio_thread.start()

    # socket = threading.Thread(target=socketio.run, args=(app,))
    # socket.start()

    socketio.run(app)