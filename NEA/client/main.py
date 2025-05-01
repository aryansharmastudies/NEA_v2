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
from threading import Timer
import time
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
import re
import queue
from datetime import datetime
import uuid
import base64
import struct
import time

'''
Basically, in order to sync folders, we have sync_queue with the different
folders/files that need to be synced. 
sync_active and sync_worker are used to control the events from sync_queue 
into the class outgoing!
'''
sync_active = threading.Event()
sync_active.clear()  # Sync is paused initially

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
    
log()  

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

class Folder(db.Model):
    folder_id = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(100))
    # mac_addr = db.Column(db.String(100))
    path = db.Column(db.String(255))
    type = db.Column(db.String(50))
    size = db.Column(db.Integer)

class File(db.Model):
    folder_id = db.Column(db.String(100), primary_key=True)
    path = db.Column(db.String(255), primary_key=True) 
    size = db.Column(db.Integer)
    hash = db.Column(db.String(32))  # MD5 hash = 32 chars NOTE: it automatically hashes the file.
    version = db.Column(db.String(10))

    def __init__(self, folder_id, path, size=None, hash=None, version='v1.0'):
        self.folder_id = folder_id
        self.path = path
        self.size = size or self._find_size()
        self.version = version
        self.hash = hash or self._find_hash() # basically, if hash is None, then use _find_hash to compute it!!

    def _find_size(self):
        try:
            return os.path.getsize(self.path)
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path {self.path} does not exist.")
    
    def _find_hash(self):
        hash_md5 = hashlib.md5()
        try:
            with open(self.path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    hash_md5.update(block)
            return hash_md5.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path {self.path} does not exist.")

        
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
    
    # Ensure alerts exist in session
    if 'alerts' not in session:
        session['alerts'] = []
        
    socketio.emit('alerts', session['alerts'])
    logging.info(f'sending alerts to frontend!: {session["alerts"]}')
    
    # Rest of the existing code...
    socketio.emit('users_devices_data', session['users_and_devices'])
    logging.info(f'sending users and devices data to frontend!: {session["users_and_devices"]}')
    socketio.emit('folder_data', session['folder_data'])
    logging.info(f'sending folder data to frontend!: {session["folder_data"]}')

@socketio.on('request_users_devices')
def handle_users_devices_request():
    try:
        if 'users_and_devices' in session and session['users_and_devices']:
            socketio.emit('users_devices_data', session['users_and_devices'])
        else:
            socketio.emit('users_devices_data', {})
            logging.warning("No users and devices data available")
    except Exception as e:
        logging.error(f"💥 Error in WebSocket request_users_devices: {e}", exc_info=True)
        emit('users_devices_data', {'error': str(e)})
    
@socketio.on('request_folders')
def handle_folder_request():
    if 'user' not in session:
        return
    
    # Get folders from database
    folders = Folder.query.all()
    folder_list = []
    
    mac_addr = get_mac()

    for folder in folders:
        folder_list.append([
            mac_addr,
            folder.folder_id,
            folder.name,
            folder.path,
            folder.type
        ])
    

    # TODO rather ask server for the folders instead of getting it from the database.

    # Send back to client
    folder_data = {'folders': folder_list}
    logging.info(f'sending folder data to frontend via dedicated function!: {folder_data}')
    emit('folder_data', folder_data)

@socketio.on('check_sync_status')
def handle_sync_status(data):
    folder_id = data.get('folder_id')
    
    try:
        # Find the folder in dir.json
        folder_path = None
        for path, info in dirs.items():
            if info.get('id') == folder_id:
                folder_path = path
                break
        
        if not folder_path:
            emit('sync_status', {'status': 'not_found', 'folder_id': folder_id})
            return
            
        # Get folder size and file count
        folder_size = 0
        file_count = 0
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    size = os.path.getsize(file_path)
                    folder_size += size
                    file_count += 1
                except:
                    pass
        
        # Update dirs with the latest size
        dirs[folder_path]['size'] = folder_size
        
        # Check if folder is still syncing or complete
        with app.app_context():
            # Count expected files from database
            expected_count = db.session.query(File).filter_by(folder_id=folder_id).count()
            
            # If we have pending tasks in sync_queue for this folder, it's still syncing
            sync_tasks = [task for task in list(sync_queue.queue) 
                          if task.get('folder_id') == folder_id]
            
            if sync_tasks:
                status = 'syncing'
            else:
                # If no pending tasks and expected files match or exceeded, it's complete
                status = 'complete' if file_count >= expected_count else 'syncing'
                
            dirs[folder_path]['status'] = 'ACTIVE' if status == 'complete' else 'SYNCING'
            
            # Save the updated status
            with open('dir.json', 'w') as file:
                json.dump(dirs, file, indent=2)
            
            # Return status information
            emit('sync_status', {
                'status': status,
                'folder_id': folder_id,
                'file_count': file_count,
                'folder_size': folder_size,
                'expected_count': expected_count
            })
            
    except Exception as e:
        logging.error(f"Error checking sync status: {e}", exc_info=True)
        emit('sync_status', {'status': 'error', 'message': str(e), 'folder_id': folder_id})

# @socketio.on('connect')
# def handle_connect():
#     global active_session
#     active_session = {}
#     for key, value in session.items():
#         active_session[key] = value
#     logging.info(f'✅ active_session set: {active_session}')

########## WEBSITE ##############################
@app.route('/pair', methods=['POST','GET'])
def pair():
    if request.method == 'POST':
        session.permanent = True
        server_name = request.form['nm'] # nm is dictionary key.
        logging.info(f'server_name: {server_name}')
        try:  # TODO 🆘 - USE THE SEND FUNCTION!!!
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_name, 8000))
            json_data = json.dumps({'action': 'ping', 'ip_addr':ip})
            logging.info(f'ping sent: {json_data}') 
            s.send(json_data.encode('utf-8'))       # TODO 🆘 MAYBE USE SEND FUNCTION TO GENERALISE EVERYTHING?
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
        if 'server_name' in session and 'user' in session:
            # TODO 🆘 - ASK SERVER IF USER IS IN DATABASE. IF YES, REDIRECT TO DASHBOARD.
            flash(f'Already Connected with {session["server_name"]} and logged in!', 'info')
            return redirect(url_for('dashboard'))
        elif 'server_name' in session:
            # TODO 🆘 - PING SERVER TO SEE IF IT IS ACTIVE.
            flash(f'Already Connected with {session["server_name"]}!', 'info')
            return redirect(url_for('login'))
        
    for key, value in session.items():
        active_session[key] = value
    logging.info(f'✅ active_session dict: {active_session}')
    return render_template('pair.html') # if the user is not logged in, then redirect to login page.
    
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

            active_session['user'] = user
            logging.info(f'active_session dict: {active_session}') # global dictionary of session that can be passed to threads

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
    
        for key, value in session.items():
            active_session[key] = value
        logging.info(f'✅ active_session dict: {active_session}')
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
        # if 'user' in session and 'server_name' in session:
        #     logging.info(f'Already Logged In {session["user"]} in Server {session["server_name"]}!')
        #     flash('Already Logged In! to register, please log out', 'info')
        #     return redirect(url_for('dashboard'))
        if 'server_name' not in session:
            flash('You are not connected to a server!', 'info')
            return redirect(url_for('pair'))
        
        for key, value in session.items():
            active_session[key] = value
        logging.info(f'✅ active_session dict: {active_session}')
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
        
        elif action == 'add_folder': # 🔴 don't think this is in use.
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

        for key, value in session.items():
            active_session[key] = value
        logging.info(f'✅ active_session dict: {active_session}')

        active_session['user'] = session['user']
        active_session['server_name'] = session['server_name']
        logging.info(f'active_session updated: {active_session}')

        mac_addr = get_mac()
        ip_tracking_data = json.dumps({'action': 'track', 'ip_addr':ip, 'user':session['user'], 'mac_addr':mac_addr}) # dont matter if user's registerd device.
        logging.info(f'tracking_data sent: {ip_tracking_data}')
        status, status_msg, data = send(ip_tracking_data)        
        session['alerts'] = data
        logging.info(f'storing alerts to sessions!: {data}')

        folder_data = json.dumps({'action': 'request', 'data': {'folders':{ 'mac_addr': mac_addr, 'folder_id':None, 'name':None, 'path':None, 'type':None}}})
        logging.info(f'getting folder data... sending: {folder_data}')
        data = send(folder_data)
        logging.info(f'folder data received: {data}')
        session['folder_data'] = data
        logging.info(f"Added folder_data to session: {session['folder_data']}")

        user_and_device_data = json.dumps({'action': 'request', 'data': {'users': {'user_id': None, 'name': None}, 'devices': {'user_id': None, 'name': None}}})
        logging.info(f'getting users and devices info... sending: {user_and_device_data}')
        data = send(user_and_device_data)
        logging.info(f'users and devices data: {data}')

        #{'devices': [{'name': 'AE86', 'user_id': 1}, {'name': 'RX-7', 'user_id': 2}, {'name': 'AE85', 'user_id': 3}], 'users': [{'name': 'takumi', 'user_id': 1}, {'name': 'ryosuke', 'user_id': 2}, {'name': 'itsuki', 'user_id': 3}]}
        if data == False:
            logging.info(f'users and devices data: {data}')
            session['users_and_devices'] = {}
            flash('Server is offline, please try again!', 'info')
            return render_template('dashboard.html', server_name=session['server_name'], 
                                user=session['user'], 
                                random_folder_id=get_random_id(),
                                mac_addr=mac_addr,
                                status=session['connected_to_server']) # pass in server_name to the dashboard.html file.
        else:
            devices = data['devices']
            users = data['users']

            id_to_users = {}
            users_and_device = {}
            
            for user in users:
                id_to_users[user['user_id']] = user['name']
                users_and_device[user['name']] = []

            for device in devices:
                username = id_to_users[device['user_id']]
                users_and_device[username].append(device['name'])

            session['users_and_devices'] = users_and_device
            logging.info(f'Added users and devices to session: {session["users_and_devices"]}')
        
        if status == '200':
            if not sync_active.is_set():
                sync_active.set() # 🧵

        # socketio.emit('alerts', data) #⭐
        # echo_alerts(data) #⭐
        # socketio.emit('message', 'new notification!!!', broadcast=True)
        # change_message('new notification!!!')

        # TODO 🆘 - get any notifications from the server.
        return render_template('dashboard.html', server_name=session['server_name'], 
                                user=session['user'], 
                                random_folder_id=get_random_id(),
                                mac_addr=mac_addr,
                                status=session['connected_to_server'])
    
    elif 'server_name' in session:
        flash('You are not logged in!', 'info')
        return render_template('login.html')
    else:    
        flash('You are not connected to a server!', 'info')
        return render_template('pair.html')
    
@app.route('/accept_share', methods=['POST'])
def accept_share():
    try:
        data = request.json
        folder_id = data.get('folder_id')
        folder_label = data.get('folder_label')
        folder_path = data.get('folder_path')
        device_name = data.get('device_name')
        index = int(data.get('index', 0))
        
        # Expand user directory
        expanded_path = os.path.expanduser(folder_path)
        
        # Create folder data
        folder_data = {
            'action': 'accept_share',
            'folder_id': folder_id,
            'folder_label': folder_label,
            'directory': expanded_path,
            'folder_type': 'sync_bothways',  # Default to sync both ways
            'username': session.get('user'),
            'mac_addr': get_mac()
        }
        
        # Send acceptance to server
    
        status = send(json.dumps(folder_data))
        logging.info(f'accept_share status from server: {status}')
        
        if str(status) == '200' or status == '201':
            # Create the local directory
            os.makedirs(expanded_path, exist_ok=True)
            
            # Add folder to dir.json for tracking
            dirs[expanded_path] = {
                'id': folder_id,
                'label': folder_label,
                'type': 'sync_bothways',
                'size': 0,
                'status': 'SYNCING'  # Set initial status to syncing
            }
            
            # Persist the directory configuration
            with open('dir.json', 'w') as file:
                json.dump(dirs, file, indent=2)
            
            # Add to watchdog if it's running
            if observer.is_alive():
                observer.schedule(event_handler, expanded_path, recursive=True)
                logging.info(f'Added {expanded_path} to watchdog!')
            
            # Add folder to database
            new_folder = Folder(
                folder_id=folder_id, 
                name=folder_label, 
                path=expanded_path, 
                type='sync_bothways', 
                size=0
            )
            db.session.add(new_folder)
            db.session.commit()
            logging.info(f'Added folder to database: {new_folder}')
            
            # Remove from alerts
            if 'alerts' in session and len(session['alerts']) > index:
                session['alerts'].pop(index)
                
            # Display success message
            flash(f"Folder '{folder_label}' accepted! Files will sync automatically.", 'info')
            
            # Return success response with sync status
            return jsonify({
                'status': 'success', 
                'message': 'Share accepted and synchronization started',
                'folder_id': folder_id,
                'folder_label': folder_label,
                'folder_path': folder_path
            })
        else:
            return jsonify({'status': 'error', 'message': 'Server returned an error'})
            
    except Exception as e:
        logging.error(f"Error accepting share: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/decline_share', methods=['POST'])
def decline_share():
    try:
        data = request.json
        folder_id = data.get('folder_id')
        device_name = data.get('device_name')
        index = int(data.get('index', 0))
        
        # Create decline data
        decline_data = {
            'action': 'decline_share',
            'folder_id': folder_id,
            'user': session.get('user'),
            'device_name': device_name
        }
        
        # Send decline to server
        server_response = send(json.dumps(decline_data))
        
        # Remove from alerts
        if 'alerts' in session and len(session['alerts']) > index:
            session['alerts'].pop(index)
            
        return jsonify({'status': 'success', 'message': 'Share declined'})
            
    except Exception as e:
        logging.error(f"Error declining share: {e}")
        return jsonify({'status': 'error', 'message': str(e)})
    
@app.route("/get_users_and_devices", methods=["GET"])
def get_users_and_devices():
    # return jsonify({'error': 'GET method not allowed'}), 405
    try:
        json_data = json.dumps({'action': 'request', 'data': {'users': ['user_id', 'name'], 'devices': ['user_id', 'name']}})
        logging.info(f'getting users and devices info... sending: {json_data}')
        data = send(json_data)
        logging.info(f'users and devices data: {data}')

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
    
    except Exception as e:
        logging.error(f"💥 Error in /get_users_and_devices: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
@app.route("/delete_folder", methods=["POST"])
def delete_folder():
    data = request.json
    folder_id = data.get('folder_id')
    
    if not folder_id:
        return jsonify({"status": "error", "message": "No folder ID provided"})
    
    try:
        # Delete folder from database
        folder = Folder.query.filter_by(folder_id=folder_id).first()
        if folder:
            db.session.delete(folder)
            db.session.commit()
            
            # Also delete from server
            server_message = json.dumps({
                "action": "delete_folder",
                "folder_id": folder_id,
                "user": session.get('user', 'unknown')
            })
            
            status = send(server_message)
            if status == '200':
                flash(f"Folder '{folder_id}' deleted successfully!", 'info')
                return jsonify({"status": "success", "message": "Folder deleted successfully"})
            else:
                flash(f"Failed to delete folder '{folder_id}' on server.", 'error')
                return jsonify({"status": "error", "message": "Failed to delete folder on server"})
        else:
            return jsonify({"status": "error", "message": "Folder not found"})
    except Exception as e:
        db.session.rollback()
        logging.error(f"💥 Error in delete_folder: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)})
    
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
        session['connected_to_server'] = False
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
    session['connected_to_server'] = False
    logging.info(f'session after logging out: {session}')
    return redirect(url_for('login'))

# 😳
@app.route("/submit_folder", methods=["POST"])
def submit_folder():
    # Get the JSON data from the request
    data = request.get_json()
    mac_addr = get_mac()
    data['mac_addr'] = mac_addr
    data['user'] = active_session['user']
    logging.info(f'DATA FROM ADDING FOLDER FORMS(front front end)!: {data}')
    data = json.dumps(data)
    status, status_msg = send(data)
    logging.info(f'submit_folder status: {status}')
    if status == '201':
    # Return a response
        mkdir(json.loads(data)) # 🥝
        return jsonify({'status': 'success', 'message': 'Folder added successfully'})
    else: 
        return jsonify({'status': 'failure', 'message': 'Folder not added, please try again'})
# 😳

def mkdir(data): # 🥝
    folder_id = data['folder_id']
    folder_label = data['folder_label']
    folder_type = data['folder_type']
    raw_dir = data['directory']
    formatted_dir = os.path.expanduser(raw_dir) # for linux it will add /home/user/ and for windows it will add C:/User/username/
    logging.info(f'creating formatted directory: {formatted_dir}')
    os.makedirs(formatted_dir, exist_ok=True)

    dirs[formatted_dir] = {}
    dirs[formatted_dir]['id'] = folder_id
    dirs[formatted_dir]['label'] = folder_label
    dirs[formatted_dir]['type'] = folder_type
    dirs[formatted_dir]['size'] = 0
    dirs[formatted_dir]['status'] = 'ACTIVE'
    logging.info(f'dir.json: {dirs}')

    with open('dir.json', 'w') as file:
        json.dump(dirs, file, indent=2)

    if observer.is_alive():
        observer.schedule(event_handler, formatted_dir, recursive=True)
        logging.info(f'added {formatted_dir} to watchdog!')
    else:
        logging.info(f'watchdog is not alive, cannot add {formatted_dir}!')
    
    ################# adding folder to database! #################
    new_folder = Folder(folder_id=folder_id, name=folder_label, path=formatted_dir, type=folder_type, size=0)
    db.session.add(new_folder)
    db.session.commit()
    logging.info(f'added folder to database: {new_folder}')
    #############################################################
    event_id = generate_event_id()
    initializer = FolderInitializer(event_id, formatted_dir, folder_id)
    logging.info(f'Created FolderInitializer Object: {initializer}')
    initializer.preorderTraversal()
    logging.info(f'========Completed Folder Traversal!========')
    del initializer

################################# folder traversal algo ################################

# NOTE: This class is used to traverse the folder and add files to the database as well as to the sync queue!!!

class FolderInitializer:
    def __init__(self, event_id, path, folder_id, event_type="created", origin="initialise"):
        self.event_id = event_id
        self.path = path
        self.folder_id = folder_id
        self.event_type = event_type
        self.origin = origin

    def _find_hash(self, full_path) -> str:
        hash_md5 = hashlib.md5()
        try:
            with open(full_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    hash_md5.update(block)
            return hash_md5.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path {full_path} does not exist.")
        
    def preorderTraversal(self):
        stack = [self.path]
        directories = []
        files = []

        while stack:
            current = stack.pop()
            logging.info(f'📂 Traversing: {current}')
            directories.append(current)

            event = {
                "id": self.event_id,
                "event_type": self.event_type,
                "src_path": current,
                "is_dir": True,
                "origin": "mkdir",
                "folder_id": self.folder_id,
                }
            sync_queue.put(event)

            try:
                children = os.listdir(current)
            except PermissionError:
                logging.error(f'❌ Permission denied: {current}')
                continue

            for item in reversed(children):  # reversed to keep the order of traversal consistent.
                full_path = os.path.join(current, item)
                if os.path.isdir(full_path):
                    stack.append(full_path)
                else:
                    logging.info(f'📖 Found file: {full_path}')
                    files.append(full_path)
                    event = {
                        "id": self.event_id,
                        "event_type": self.event_type,
                        "src_path": full_path,
                        "is_dir": False,
                        "origin": "mkdir",
                        "folder_id": self.folder_id,
                        "hash": self._find_hash(full_path),
                        "size": os.path.getsize(full_path)
                        }
                    sync_queue.put(event)

                    new_file = File(folder_id=self.folder_id, path=full_path, hash=event['hash'], size=event['size'])
                    try:
                        db.session.add(new_file)
                        db.session.commit()
                        logging.info(f'File {full_path} added to database with version v1.0')
                    except Exception as e:
                        db.session.rollback()  # just used to rollback in case of errors.
                        logging.error(f'❌ Failed to add {full_path} to database: {e}')
        
        logging.info('✅ Traversal Complete')
        logging.info(f'🗃️ Directories: {directories}')
        logging.info(f'📑 Files: {files}')

        all_events = list(sync_queue.queue)
        with open("sync_queue.json", "w") as f:
            json.dump(all_events, f, indent=2)
        
        logging.info(f'Sync queue saved to sync_queue.json')


'''
                TODO 🆘 : for all the files that were added to the database, sum up the total file size and assign it to the folder size.

'''
########## SEND #################################
def send(json_data): # 🛫
        start = time.time()
        logging.info(f'sending data to server: {json_data}')
        try: 
            logging.info(f'trying to connect to server: {session["server_name"]} on port 8000')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # s.connect((session['server_name'], 8000))
            s.connect(('192.168.1.75', 8000))
            logging.info(f'Connected to server: {session["server_name"]} on port 8000')
            session['connected_to_server'] = True

        except: 
            logging.info(f'503 Server Offline')
            flash(f'Server inactive, please retry!', 'info')
            session['connected_to_server'] = False
            
            action = json.loads(json_data)['action']
            if action in ['login', 'register_user', 'add_device', 'add_folder']:
                return '503', 'server offline'
            elif action in ['track']:
                return '503', 'server offline', False
            elif action in ['request', 'accept_share', 'decline_share']:
                return False
            
        s.send(json_data.encode('utf-8')) # sending data to server 📨
        json_response = s.recv(4096).decode('utf-8') # server's response back 📩 # TODO 🆘 recieves 1024 bits, add buffering feature !!
        logging.info(f'server response: {json_response}, type: {type(json_response)}')
        end = time.time()
        logging.info(f'⏰ time taken to send data: {end - start} seconds')

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
        elif action in ['accept_share', 'decline_share']:
            return status

########## HANDLE SERVER MESSAGE ################

def handle_server_message(json_message, server_socket):
    if json_message['action'] == 'authorise':
        logging.info(f'authorisation recieved: {json_message}')
        if  json_message['user'] == active_session['user']:

            # try request.session['user']
            message = json.dumps({'status_code': '200'})
            server_socket.send(message.encode('utf-8'))
        else:
            message = json.dumps({'status_code': '404'})
            server_socket.send(message.encode('utf-8'))
    elif json_message['action'] == 'share_folder':
        # need to create a popup on dashboard to accept or decline the folder.
        logging.info(f'sharing folder: {json_message}')
        # TODO 🆘 toggle the modal to popup.
        random_folder_id = get_random_id()
        return render_template('dashboard.html', server_name=active_session['server_name'], user=active_session['user'], random_folder_id=random_folder_id, share_folder=json_message)
        # continue with the rest of code.

        # TODO 🆘 - MAKE SESSION GLOBAL!.


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
    run_simple("0.0.0.0", 5000, app, use_reloader=False)

def run_socketio():
    """Function to run the Flask-SocketIO server."""
    print("Running SocketIO server...")
    socketio.run(app)
#################################### WATCHDOG # 🐕 #####################################

################################# regex ################################################

TEMP_PATTERNS_REGEX = re.compile(
    r"(^.*\.swp$|^.*\.tmp$|^\.goutputstream.*$|^~.*$|^.*\.bak$|^.*\.part$)"
)

def is_temp_file(filepath):
    filename = os.path.basename(filepath)
    return bool(TEMP_PATTERNS_REGEX.match(filename))

################################# regex ################################################

class MyEventHandler(FileSystemEventHandler):
    #def on_any_event(self, event: FileSystemEvent) -> None:
    #    print(event)
    def __init__(self):
        super().__init__()
        self._supressed_dirs: set[str] = set()
        self._debounce_timers = {}  # debounce timers for file modification events
        self.debounce_delay = 1.5  # seconds
        self._ignored_paths = set()

    def _get_parent_folder_id(self, file_path: str) -> str | None:
        # Convert to absolute path to ensure consistent comparisons
        parent_dir = os.path.abspath(os.path.dirname(file_path))
        logging.info(f'parent_dir: {parent_dir}')
        
        # Only query the needed columns (folder_id and path)
        # if not hasattr(self, '_cached_folders') or self._cached_folders is None:
        with app.app_context():
            self._cached_folders = [(f.folder_id, os.path.abspath(f.path)) 
                                    for f in Folder.query.with_entities(Folder.folder_id, Folder.path).all()]
            logging.info(f'Loaded {len(self._cached_folders)} folder candidates with folder_id and path only')
    
        # Variables to track the best match
        best_folder_id = None
        best_path_length = -1
        
        # Iterate through all folders to find the best match
        for folder_id, folder_path in self._cached_folders:
            logging.info(f'Checking folder: {folder_id} - {folder_path}')
            # Ensure exact directory match by adding separator
            prefix = folder_path.rstrip(os.sep) + os.sep
            prefix_length = len(prefix)
            logging.info(f'prefix: {prefix} - prefix_length: {prefix_length}')
            
            # Check if this folder contains the file's parent directory
            # Either the parent_dir exactly matches folder_path (without trailing separator)
            # or parent_dir starts with folder_path + separator (indicating proper directory hierarchy)
            if parent_dir == folder_path.rstrip(os.sep) or parent_dir.startswith(prefix):
                logging.info(f'Found match: {folder_id} - {folder_path}')
                # If this path is longer than our current best, it's more specific
                if prefix_length > best_path_length:
                    best_folder_id = folder_id
                    best_path_length = prefix_length
                    logging.info(f'Found better match: {folder_id} - {folder_path}')
        
        # Return the best match if one was found
        if best_folder_id:
            logging.info(f'Best folder match for {parent_dir}: {best_folder_id}')
            return best_folder_id
        else:
            logging.warning(f'No matching folder found for {parent_dir}')
            return None

    def _persist_queue(self):
        try:
            all_events = list(sync_queue.queue)
            with open("sync_queue.json", "w") as f:
                json.dump(all_events, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to persist sync queue: {e}")

    def _find_hash(self):
        hash_md5 = hashlib.md5()
        try:
            with open(self.src_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    hash_md5.update(block)
            return hash_md5.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path {self.path} does not exist.")
    
    def generate_event_id(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        uid = str(uuid.uuid4())[:6]  # Short unique suffix (6 hex chars)
        return f"event_{timestamp}_{uid}"

    def clean(self, event):
        removed_created = False
        removed_modified = False
        current_event_type = event.event_type
        temp_events = []

        while not sync_queue.empty():
            item = sync_queue.get()
            if item['src_path'] == event.src_path:
                if item['event_type'] == 'created':
                    if current_event_type == 'deleted':
                        removed_created = True
                        logging.info(f"🧹 Removed 'created' event for {event.src_path}")
                        continue # dont append to temp_event
                    elif current_event_type == 'modified':
                        removed_created = True
                        logging.info(f"🧹 Removed 'created' event for {event.src_path} due to modification")
                        continue # dont append to temp_event
                elif item['event_type'] == 'modified':
                    removed_modified = True
                    logging.info(f"🧹 Removed 'modified' event for {event.src_path}")
                    continue # Dont append to temp_event
            temp_events.append(item)

        for item in temp_events:
            sync_queue.put(item)
        
        return removed_created, removed_modified
    
    def dispatch(self, event):
        path = event.src_path
        self.src_path = path
        if is_temp_file(event.src_path):
            '''
            Unfortunately using some text editiors like the one in ubuntu, 
            they dont show the file has been modified rather, they create a temp file and store
            stuff there, then when we are done, it copies it to the original file.
            So we need to ignore these temp files.

            thats why sometimes for a file modification we just see 🔵 rather than a 🟡
            '''
            logging.info(f'⚠️ Ignoring temporary file: {event.src_path}')
            return  # ❌ You should return here to **stop** processing
        
        for parent in self._supressed_dirs:
            if path.startswith(parent + os.sep):
                logging.debug(f'Supressed event for {path!r} under {parent!r}')
                return
        logging.info(f'Processing event: {event}')
        return super().dispatch(event)  # ✅ This goes ahead **only if the file is not temporary AND  if its not within supressed_dirs**

                                                # TODO 🆘 MODIFY DATABASE + ADD IT TO SYNC_QUEUE 
    def on_moved(self, event):
        
        path = event.src_path
        if path in self._ignored_paths:
            logging.debug(f"😏 Ignoring sync-generated event for {path}")
            self._ignored_paths.remove(path)  # Only suppress once!
            return
        
        logging.info(f"🟣 Moved: {event.src_path} → {event.dest_path}")

        # suppress further events from the old folder
        if event.is_directory:
            self._supressed_dirs.add(event.src_path)

        sync_queue.put({
            "id": self.generate_event_id(),
            "event_type":  "moved",
            "src_path":     event.src_path,
            "dest_path":    event.dest_path,
            "is_dir":  event.is_directory,
            "origin": "user",
            "folder_id": self._get_parent_folder_id(event.src_path) or None
        })
        self._persist_queue()
    
    def on_created(self, event):
        path = event.src_path
        if path in self._ignored_paths:
            logging.debug(f"😏 Ignoring sync-generated event for {path}")
            self._ignored_paths.remove(path)  # Only suppress once!
            return
        
        logging.info(f"🟢 Created: {event.src_path}")

        # TODO get folder_id
        # sync_queue.put
        # add to db

        # if you recreated a suppressed directory, stop suppressing it
        if event.is_directory and event.src_path in self._supressed_dirs:
            self._supressed_dirs.remove(event.src_path)
        # Only for files (not directories), look up its parent folder_id and insert
        if not event.is_directory: # i.e. if it is a file
            folder_id = self._get_parent_folder_id(event.src_path)
            logging.info(f'folder_id: {folder_id}')
            if folder_id is None:
                logging.error(f"No registered folder found for {event.src_path}; skipping DB insert")
            else:
                logging.info(f"Creating event for file: {event.src_path} in folder {folder_id}")
                sync_queue.put({
                    "id": self.generate_event_id(),
                    "event_type": "created",
                    "src_path": event.src_path, 
                    "is_dir": event.is_directory,
                    "origin": "mkdir",
                    "folder_id": folder_id, 
                    "hash": self._find_hash(),
                    "size": os.path.getsize(event.src_path)
                    })
                logging.info(f"Added to sync_queue: {event.src_path} with folder_id {folder_id}")
                
                new_file = File(folder_id=folder_id, path=event.src_path)
                logging.info(f"Creating new file object: {new_file}")
                try:
                    with app.app_context():
                        db.session.add(new_file)
                        db.session.commit()
                        logging.info(f"File {event.src_path} added to database under folder {folder_id}")
                except Exception as e:
                    with app.app_context():
                        db.session.rollback()
                    logging.error(f"❌ Failed to add {event.src_path} to database: {e}")
    
        else:
            logging.info(f"Creating event for directory: {event.src_path}")
            sync_queue.put({
                "id": self.generate_event_id(),
                "event_type": "created",
                "src_path": event.src_path,
                "is_dir": event.is_directory,
                "origin": "user",
                "folder_id": self._get_parent_folder_id(event.src_path) or None
            })

        self._persist_queue() # save to sync_queue.json
        logging.info(f'saved to sync_queue.json')
    
    def on_deleted(self, event):
        path = event.src_path
        if path in self._ignored_paths:
            logging.debug(f"😏 Ignoring sync-generated event for {path}")
            self._ignored_paths.remove(path)  # Only suppress once!
            return
        
        logging.info(f"🔴 Deleted: {event.src_path}")

        # if it was a directory, remember to suppress its children
        if event.is_directory:
            self._supressed_dirs.add(event.src_path)
        
        #### 🧹🧹🧹 checks sync_queue for any creation/deletion of current file, since delete overrides creation and modification! ####
        '''
        IF WE HAVE A FILE THAT HAS BEEN CREATED OFFLINE. 
        THEN ITS BEEN DELETED OFFLINE.
        WE HAVE TO REMOVE THE CREATED EVENT FROM THE QUEUE.

        IF WE HAVE A FILE THAT HAS BEEN MODIFIED OFFLINE. 
        THEN ITS BEEN DELETED OFFLINE.
        WE HAVE TO REMOVE THE MODIFIED EVENT FROM THE QUEUE.
        '''
        removed_created, removed_modified = self.clean(event) # 
        ###########################################################################################################################
        sync_queue.put({
            "id": self.generate_event_id(),
            "event_type":  "deleted",
            "src_path":    event.src_path,
            "is_dir":  event.is_directory,
            "origin":  "user",
            "folder_id": self._get_parent_folder_id(event.src_path) or None
        })
        
        self._persist_queue() # save to sync_queue.json
        logging.info(f'saved to sync_queue.json')
        # If it's a file, remove it from the database
        if not event.is_directory:
            try:
                with app.app_context():
                    file_to_delete = File.query.filter_by(path=event.src_path).first()
                    if file_to_delete:
                        db.session.delete(file_to_delete)
                        db.session.commit()
                        logging.info(f"File {event.src_path} deleted from database")
                    else:
                        logging.warning(f"File {event.src_path} not found in database")
            except Exception as e:
                with app.app_context():
                    db.session.rollback()
                logging.error(f"❌ Failed to delete {event.src_path} from database: {e}")
        
    
    def on_modified(self, event):
        path = event.src_path
        if path in self._ignored_paths:
            logging.debug(f"😏 Ignoring sync-generated event for {path}")
            self._ignored_paths.remove(path)  # Only suppress once!
            return
        
        if event.is_directory:
            return

        path = event.src_path

        if path in self._debounce_timers:
            self._debounce_timers[path].cancel()

        timer = Timer(self.debounce_delay, lambda: self._debounce_timers.pop(path, None))
        timer.start()
        self._debounce_timers[path] = timer

        if timer.finished:
            logging.info(f"🟡 Debounced: {path} really modified!")
            stats = os.stat(path)
            size = stats.st_size
            mtime = time.ctime(stats.st_mtime)
            logging.info(f"🟡 {path} size: {size} bytes, last modified: {mtime}")

            folder_id = self._get_parent_folder_id(path)
            if folder_id is None:
                logging.warning(f"Skipping sync for modified file {path} (no matching folder)")
                return

            self.src_path = path
            new_hash = self._find_hash()

            try:
                with app.app_context():
                    # Try to find the file in the database
                    file = File.query.filter_by(path=path).first()
                    
                    if file:
                        # File exists in database, check if content actually changed
                        if file.hash == new_hash:
                            logging.info(f"🚫 No content change detected in {path}, skipping sync")
                            return
                        else:
                            # Update the hash and size in the database since file has changed
                            logging.info(f"🟠 Content change detected in {path}, updating hash from {file.hash} to {new_hash}")
                            file.hash = new_hash
                            file.size = size
                            # Increment the version number
                            current_version = file.version
                            version_num = float(current_version[1:])  # Remove 'v' and convert to float
                            new_version_num = version_num + 0.1  # Increment by 0.1
                            file.version = f"v{new_version_num:.1f}"  # Format back to string with v prefix
                            
                            db.session.commit()
                            logging.info(f"File {path} version updated to {file.version}")
                            '''
                            OFFLINE MODIFICATION OVERRIDES OFFLINE MODIFICATION AND CREATION.
                            '''
                            removed_created, removed_modified = self.clean(event) # 🧹🧹🧹

                    else:
                        # File doesn't exist in database yet
                        logging.warning(f"File {path} not found in database but was modified. Will add to sync queue.")
                        new_file = File(folder_id=folder_id, path=path, hash=new_hash, size=size) # version will automatically be set to 1.0
                        db.session.add(new_file)
                        db.session.commit()
                        logging.info(f"File {path} added to database with version 1.0")
                        sync_queue.put({ # 
                                "id": self.generate_event_id(),
                                "event_type": "created",
                                "src_path": path, 
                                "is_dir": False,
                                "origin": session['user'],
                                "folder_id": folder_id, 
                                "hash": new_hash,
                                "size": size,
                                "folder_id": self._get_parent_folder_id(event.src_path) or None
                                })
                        logging.info(f"🟡 ---> 🟢 Added to sync_queue: {path} with folder_id {folder_id}")
                        
            except Exception as e:
                # Handle any database errors safely
                logging.error(f"Database error checking file hash: {e}")
                # Continue with sync anyway to be safe
                with app.app_context():
                    db.session.rollback()  # Ensure transaction is cleaned up
        # TODO 🆘 : MODIFICATIONS OVERRIDE OTHER MODIFICATIONS! 
            
            if removed_modified:
                logging.warning("[!] Handling modifications that override other modifications.")
                sync_queue.put({ 
                    "id": self.generate_event_id(),
                    "event_type": "modified",
                    "src_path": path,
                    "is_dir": False,
                    "origin": "user",
                    "hash": new_hash,
                    "size": size,
                    "folder_id": self._get_parent_folder_id(event.src_path) or None
                })
                self._persist_queue()
                logging.info(f'🟡 Modified file {path} added to sync_queue!')
            
            elif removed_created:
                logging.warning("[!] Handling modifications that override file creation.")
                sync_queue.put({
                    "id": self.generate_event_id(),
                    "event_type": "created",
                    "src_path": path, 
                    "is_dir": False,
                    "origin": "user",
                    "folder_id": folder_id, 
                    "hash": new_hash,
                    "size": size,
                    "folder_id": self._get_parent_folder_id(event.src_path) or None
                    })
                self._persist_queue()
                logging.info(f'🟡 ---> 🟢 Modified file {path} added to sync_queue AS CREATED!')
            
            else:
                # Handle case when neither removed_modified nor removed_created is True
                logging.info("Normal file modification detected, adding to sync queue.")
                sync_queue.put({ 
                    "id": self.generate_event_id(),
                    "event_type": "modified",
                    "src_path": path,
                    "is_dir": False,
                    "origin": "user",
                    "folder_id": folder_id,
                    "hash": new_hash,
                    "size": size,
                    "folder_id": self._get_parent_folder_id(event.src_path) or None
                })
                self._persist_queue()
                logging.info(f'🟡 Modified file {path} added to sync_queue!')
    
    def on_closed(self, event):
        logging.info(f'🔵 {event}')

event_handler = MyEventHandler()
observer = Observer()
threads = []

def start_watchdog(dirs):
    global event_handler, observer, threads

    for d in dirs:
        targetPath = str(d)
        if os.path.exists(targetPath):
            observer.schedule(event_handler, targetPath, recursive=True)
            threads.append(observer)
            dirs[d]['status'] = 'ACTIVE'
        else:
            logging.warning(f"Directory not found: {targetPath}. Removing from dirs.")
            dirs[d]['status'] = 'NOT FOUND!'
    
    with open('dir.json', 'w') as fp:
        json.dump(dirs, fp, indent=2)
    
    logging.info(f'🐕 watchdog started! 🐕')
    observer.start()

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


#################################### WATCHDOG # 🐕 #####################################

################################### SYNC-QUEUE #########################################
sync_queue = queue.Queue()

if os.path.exists("sync_queue.json"):
    with open("sync_queue.json", "r") as f:
        for item in json.load(f):
            sync_queue.put(item)
else:
    logging.info("No sync_queue.json file found. Starting with empty queue.")

def generate_event_id():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    uid = str(uuid.uuid4())[:6]  # Short unique suffix (6 hex chars)
    return f"event_{timestamp}_{uid}"


################################### SYNC-QUEUE #########################################

########################### SYNC WORKER - GLUE BETWEEN SYNC_QUEUE and OUTGOING ##################
def sync_worker(): 
    while True:
        sync_active.wait()  # Wait until resumed
        event = sync_queue.get()
        logging.info(f"Processing event: {event}")
        try:
            logging.info(f"Creating sync job for {event['src_path']}")
            sync_job = Outgoing(event)  # JUST RUNS INITIALISERS
            logging.info(f"Sync job created: {sync_job}")
            status = sync_job.start_server()  # Start the server to send the packet
            logging.info(f"Sync job status: {status}")
            
            if status:
                logging.info(f"✅ Sync job completed for {event['src_path']}")
                sync_active.set() 
            else:
                logging.error(f"❌ Sync job failed for {event['src_path']}")
                sync_active.clear()
                logging.info("⏸️Paused sync worker due to connection error.")  # Pause instead of exit
                sync_queue.put(event)  # Requeue the event
                logging.info(f"🔁Requeued event: {event}")
            
        except Exception as e:
            logging.error(f"❌ Sync failed: {e}")
            sync_active.clear()  # Pause on failure
            logging.info(f"⏸️paused sync worker due to error: {e}")
            sync_queue.put(event)  # Requeue the event
            logging.info(f"🔁Requeued event: {event}")
        
        finally:
            sync_queue.task_done()
            all_events = list(sync_queue.queue)
            with open("sync_queue.json", "w") as f:
                json.dump(all_events, f, indent=2)

# def sync_listener(): # bridges barrier between incoming data and sync class
#     incomingsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     incomingsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#     incomingsock.bind((ip, 6969))
#     logging.info(f"[+] Listening on {ip}:6969...")
#     incomingsock.listen(1) # only can recieve data from one client at a time otherwise, it can get messy.

#     while True:
#         connection, address = incomingsock.accept() # if client does s.connect((server_name, 8000))
#         logging.info(f'Connection from {address} has been established!')
#         sync_job = Incoming(address, connection)
#         logging.info(f"[+] Sync job created for {address}...")
#         sync_job.receive_metadata()
#         logging.info(f"[+] Sync job completed for {address}...")
#         connection.close()
#         logging.info(f"[-] Connection closed for {address}...")
#         del sync_job
#         logging.info(f"[-] Sync job deleted for {address}...")

########################### SYNC WORKER - GLUE BETWEEN SYNC_QUEUE and OUTGOING ##################
class Sync:
    def __init__(self):
        # self.BLOCK_SIZE = 1024 * 1024 # 1048576 Bytes -> 1 MebiByte
        self.HEADER_SIZE = 4
        self.RESPONSE_OK = b'ACK'
        self.RESPONSE_ERR = b'ERR'

class Outgoing(Sync):
    def __init__(self, event):
        super().__init__()
        self.PORT = 9696
        self.src_path = event['src_path']
        self.is_dir = event['is_dir']  # Updated to use 'is_dir' from event
        self.origin = event['origin']  # Updated to use 'origin' from event
        self.event_type = event['event_type']
        self.folder_id = event['folder_id']

        if not self.is_dir and self.event_type == 'created':
            logging.info(f"Adding packets, packet_count, hash, folder_id")
            self.packets = self.create_packet()
            self.packet_count = len(self.packets)
            self.hash = file_to_hash.get(self.src_path)
        
        elif not self.is_dir and self.event_type == 'modified':
            logging.info(f"Creating block list for modified file")
            self.blocks = self.create_blocklist() # {'hash1'={},'hash2'={},'hash3'={}} 
            self.block_count = len(self.blocks)
            self.hash = file_to_hash.get(self.src_path) or event.get('hash')
            self.packets = self.create_packet()
            self.packet_count = len(self.packets)
            with app.app_context():
                file = File.query.filter_by(path=self.src_path).first()
                if file:
                    self.version = file.version
                else:
                    self.version = 'v1.0'  # Default version

        if self.event_type == 'moved':
            self.dest_path = event['dest_path']
    
    def _build_metadata(self) -> dict:
        metadata = {
            "index":      0,
            "user":      active_session['user'],
            "event_type": self.event_type,
            "src_path":       self.src_path,
            "is_dir":     self.is_dir,
            "origin":     self.origin,
            "folder_id":  self.folder_id,
            "mac_addr": get_mac(),
        }
        if not self.is_dir and self.event_type == 'created':
            metadata['hash'] = self.hash
            metadata["packet_count"] = self.packet_count
            metadata["folder_id"] = self.folder_id
            metadata["size"] = os.path.getsize(self.src_path)
        
        elif not self.is_dir and self.event_type == 'modified':
            metadata['hash'] = self.hash
            metadata["packet_count"] = self.packet_count
            metadata["block_count"] = self.block_count
            metadata["folder_id"] = self.folder_id
            metadata["size"] = os.path.getsize(self.src_path)
            metadata["version"] = self.version
            
        
        if self.event_type == 'moved':
            metadata['dest_path'] = self.dest_path
        return metadata
    
    def get_blocksize(self) -> int:
        """Determine block size based on file size."""
        try:
            file_size = os.path.getsize(self.src_path)
            
            # Convert to MiB for easier comparison
            file_size_mib = file_size / (1024 * 1024)
            
            if file_size_mib <= 1:
                return 128 * 1024  # 128 KiB
            elif file_size_mib <= 10:
                return 512 * 1024  # 512 KiB
            elif file_size_mib <= 100:
                return 1024 * 1024  # 1 MiB
            elif file_size_mib <= 500:
                return 4 * 1024 * 1024  # 4 MiB
            else:
                return 8 * 1024 * 1024  # 8 MiB
        except FileNotFoundError:
            logging.error(f"File not found: {self.src_path}")
            return 128 * 1024  # Default to smallest block size if file not found
        except Exception as e:
            logging.error(f"Error getting file size: {e}")
            return 128 * 1024  # Default to smallest block size on error

    def create_blocklist(self) -> dict: # Returns: dictionary mapping block hashes to their offset and size.
        if self.event_type != 'modified':
            return {}
        
        block_size = self.get_blocksize()
        block_list = {}
        
        try:
            with open(self.src_path, 'rb') as f:
                offset = 0
                while True:
                    block = f.read(block_size)
                    if not block:  # EOF - end of file
                        break
                    
                    block_hash = hashlib.md5(block).hexdigest()
                    block_list[block_hash] = {
                        "offset": offset,
                        "size": len(block) # Use actual size in case of partial blocks
                    }

                    offset += len(block)
            # Store the block list in self
            logging.info(f"🧱 Block list created with {len(block_list)} entries.")
            return block_list
        
        except FileNotFoundError:
            logging.error(f"File not found: {self.src_path}")
            return {}
        except Exception as e:
            logging.error(f"Error creating block list: {e}")
            return {}
    
        '''
        block_list looks like {'hash1'={},'hash2'={},'hash3'={}}
        '''
    
    def create_packet(self) -> list:
        # Use dynamic block size based on file size
        block_size = self.get_blocksize()
        
        with open(self.src_path, 'rb') as f:
            file_data = f.read()

        blocks = [file_data[i:i + block_size] for i in range(0, len(file_data), block_size)]
        return [
            {
                "index": i,
                "data": base64.b64encode(block).decode(),
                "checksum": hashlib.md5(block).hexdigest()
            }
            for i, block in enumerate(blocks)
        ]

    def send_packet(self, outgoingsock: socket.socket, packet: dict) -> None:
        payload = json.dumps(packet).encode('utf-8')
        header = struct.pack('!I', len(payload))
        message = header + payload  # You can join header and payload using the '+' operator
        sent = False   
        while not sent:
            outgoingsock.sendall(message)
            response = outgoingsock.recv(3)
            if response == self.RESPONSE_OK:
                # logging.info(f"[+] Packet {packet['index']} transmitted successfully.") # 🔔
                sent = True
            else:
                logging.info(f"[-] Packet {packet['index']} failed checksum, retrying...")

    def start_server(self) -> bool:
        outgoingsock = socket.socket()
        try:
            logging.info(f"Connecting to server at {active_session['server_name']}:{self.PORT}")
            outgoingsock.connect((active_session['server_name'], self.PORT))
            logging.info(f"[+] Connected to server at {active_session['server_name']}:{self.PORT}")
            
            metadata = self._build_metadata()
            logging.info(f"[+] Sending metadata: {metadata}")
            self.send_packet(outgoingsock, metadata) # metadata is dict
            logging.info(f"[+] Metadata sent: {metadata}")

            # Send blocklist for modified files
            if self.event_type == 'modified' and hasattr(self, 'blocks'):
                blocklist_packet = {
                    "index": "blocklist",
                    "blocklist": self.blocks
                }
                logging.info(f"[+] Sending block list for modified file")
                self.send_packet(outgoingsock, blocklist_packet)
                logging.info(f"[+] Block list sent for modified file")

                return True

            # Send file packets for created and modified files
            if hasattr(self, 'packets'):
                logging.info(f"[+] Sending {len(self.packets)} packets for {self.src_path}")
                for packet in self.packets:
                    self.send_packet(outgoingsock, packet)
                    # logging.info(f"[+] Packet {packet} sent.") # 🔔
        
            logging.info("[+] All packets sent.")
        except Exception as e:
            logging.error(f"❌ Failed to connect to server: {e}")
            return False
        finally:
            outgoingsock.close()
    
        return True
########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################


def sync_listener(): # bridges barrier between incoming data and sync class
    incomingsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    incomingsock.bind((ip, 6969))
    logging.info(f"[+] Listening on {ip}:6969...")
    incomingsock.listen(1) # only can recieve data from one client at a time otherwise, it can get messy.

    while True:
        connection, address = incomingsock.accept() # if client does s.connect((server_name, 8000))
        logging.info(f'Connection from {address} has been established!')
        sync_listener_job = Incoming(address, connection)
        logging.info(f"[+] Sync job created for {address}...")
        sync_listener_job.receive_metadata()
        logging.info(f"[+] Sync job completed for {address}...")
        connection.close()
        logging.info(f"[-] Connection closed for {address}...")
        del sync_listener_job
        logging.info(f"[-] Sync job deleted for {address}...")

class Incoming(Sync):
    def __init__(self, address, connection):
        super().__init__()
        self.PORT = 6969
        self.folderSyncInProgress = False
        self.address = address
        self.connection = connection
        
    def receive_metadata(self) -> None:

        metadata = self.receive_valid_packet(self.connection, 0)
        logging.info(f"[+] Metadata received: {metadata}")
        event_type = metadata['event_type']

        if event_type in ['created', 'deleted', 'modified', 'moved']:
            # event_handler._supressed_dirs(metadata['src_path'])
            event_handler._ignored_paths.add(metadata['src_path'])
            logging.info(f"😏 Ignoring sync-generated event for {metadata['src_path']}")

        if metadata['is_dir'] and event_type == 'created':
            logging.info(f"[+] Initiating CreateDir.apply()")
            CreateDir(metadata, self.address).apply()
                        
        elif not metadata['is_dir'] and event_type == 'created':
            logging.info(f"[+] Initiating CreateFile.apply()")
            CreateFile(metadata, self.address, self.connection).apply()
            
        elif event_type == 'deleted':
            logging.info(f"[+] Initiating Delete.apply()")
            Delete(metadata, self.address).apply()
            
        elif event_type == 'moved':
            logging.info(f"[+] Initiating Move.apply()")
            Move(metadata, self.address).apply()

        elif not metadata['is_dir'] and event_type == 'modified':
            logging.info(f"[+] Initiating Modify.apply()")
            Modify(metadata, self.address, self.connection).apply()
        
        elif metadata['event_type'] == 'request':
            src_path = metadata['src_path']
            block_offset = metadata.get('block_offset', 0)
            block_size = metadata.get('block_size', 0)
            block_hash = metadata.get('block_hash')
            
            # Create response event for Outgoing class
            response_event = {
                'event_type': 'block_response',
                'src_path': src_path,
                'is_dir': False,
                'origin': 'response',
                'block_offset': block_offset,
                'block_size': block_size,
                'block_hash': block_hash
            }
            
            # Read the requested block
            block_data = self.read_block(src_path, block_offset, block_size, block_hash)
            
            # Send the block data back
            self.send_block_data(self.connection, response_event, block_data)
            logging.info(f"[BLOCK HANDLER] Sent block data for {block_hash[:8]}...")
            
            # Keep connection open briefly to ensure server receives all data
            time.sleep(0.5)
        # elif event_type == 'modified':
        #     logging.info(f"[+] Initiating Modify.apply()")
        #     Modify(metadata, self.address, self.connection).apply()
        
        # If this was part of a folder sync, update the UI via Socket.IO
        
        elif metadata['event_type'] == 'establish':
            src_path = metadata['src_path']
            dirs[src_path] = {}
            dirs[src_path]['id'] = metadata['folder_id']
            dirs[src_path]['label'] = metadata['folder_label']
            dirs[src_path]['type'] = metadata['type']
            dirs[src_path]['size'] = metadata['size']
            dirs[src_path]['status'] = 'ACTIVE'
            logging.info(f'dir.json: {dirs}')

            with open('dir.json', 'w') as file:
                json.dump(dirs, file, indent=2)

            if observer.is_alive():
                observer.schedule(event_handler, src_path, recursive=True)
                logging.info(f'added {src_path} to watchdog!')
            else:
                logging.info(f'watchdog is not alive, cannot add {src_path}!')
            

        
        if self.folderSyncInProgress and 'folder_id' in metadata:
            socketio.emit('folder_sync_progress', {
                'folder_id': metadata['folder_id'],
                'event_type': event_type,
                'is_dir': metadata['is_dir'],
                'path': os.path.basename(metadata['src_path'])
            })
        
    def listen_for_requests(self):
        """Listen for block requests from server on port 6969."""
        request_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        request_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            request_socket.bind((ip, self.PORT))
            request_socket.listen(5)
            logging.info(f"[BLOCK LISTENER] Started on {ip}:{self.PORT}, waiting for block requests...")
            
            while True:
                self.connection, self.address = request_socket.accept()
                self.connection.settimeout(10.0)  # Add timeout to prevent hanging
                logging.info(f"[BLOCK LISTENER] Received connection from {self.address}")
                # Handle request in a separate thread to allow multiple concurrent requests
                threading.Thread(target=self.handle_request, args=(self.connection, self.address), daemon=True).start()

        except Exception as e:
            logging.error(f"[BLOCK LISTENER] Error: {e}")
        finally:
            request_socket.close()
    
    def recv_exact(self, connection, num_bytes):
        """Receive an exact number of bytes from the socket."""
        data = b''
        while len(data) < num_bytes:
            packet = connection.recv(num_bytes - len(data))
            if not packet:
                raise ConnectionError("Connection closed prematurely")
            data += packet
        return data
    
    def receive_valid_packet(self, connection, index):
        logging.info(f"Receiving packet {index}...")
        """Receive and validate a packet."""
        header = self.recv_exact(connection, self.HEADER_SIZE)
        payload_length = struct.unpack('!I', header)[0]
        payload = self.recv_exact(connection, payload_length)
        payload = json.loads(payload.decode())
        
        if isinstance(index, str) or index == 0:  # Metadata or special packet
            connection.send(self.RESPONSE_OK)
            logging.info(f'valid packet {index} received sent ACK')
            return payload
            
        decoded_data = base64.b64decode(payload['data'])
        checksum = payload['checksum']
        
        actual_checksum = hashlib.md5(decoded_data).hexdigest()
        if actual_checksum == checksum:
            logging.info(f"[BLOCK LISTENER] Checksum verified for packet {index}")
            connection.send(self.RESPONSE_OK)
            return decoded_data, actual_checksum
        else:
            connection.send(self.RESPONSE_ERR)
            logging.error(f"[BLOCK LISTENER] Checksum mismatch on packet {index}")
            return None
    
    def handle_request(self, connection, address):
        """Handle a block request from the server."""
        try:
            # Receive the request metadata
            sync_job = self.receive_metadata(connection, 0)
                
        except Exception as e:
            logging.error(f"[BLOCK HANDLER] Error handling request: {e}")
        finally:
            # Log before closing to help with debugging
            logging.info("[BLOCK HANDLER] Closing connection after handling request")
            connection.close()
    


            

    def read_block(self, src_path, offset, size, expected_hash):
        """Read a block from the specified file at given offset."""
        try:
            with open(src_path, 'rb') as f:
                f.seek(offset)
                block_data = f.read(size)
                
                # Verify the hash
                self.actual_hash = hashlib.md5(block_data).hexdigest()
                logging.info(f'checking Actual hash: {self.actual_hash} against expected hash: {expected_hash}')
                if self.actual_hash != expected_hash:
                    logging.warning(f"[BLOCK HANDLER] Hash mismatch: expected {expected_hash}, got {self.actual_hash}")
                else:
                    logging.info(f"[BLOCK HANDLER] Hash verified for block {expected_hash[:8]}")
                return block_data
                    
        except FileNotFoundError:
            logging.error(f"[BLOCK HANDLER] File not found: {src_path}")
            return None
        except Exception as e:
            logging.error(f"[BLOCK HANDLER] Error reading block: {e}")
            return None
    
    def send_block_data(self, connection, event, block_data):
        """Send block data back to the server."""
        try:
            if not block_data:
                # Send error metadata
                error_metadata = {
                    'index': 0,
                    'event_type': 'block_response',
                    'status': 'error',
                    'message': 'Failed to read block data',
                    'is_dir': False,
                    'src_path': event['src_path'],
                    'packet_count': 0
                }
                payload = json.dumps(error_metadata).encode('utf-8')
                header = struct.pack('!I', len(payload))
                message = header + payload
                connection.sendall(message)
                response = connection.recv(3)
                logging.info(f"[BLOCK HANDLER] Error metadata acknowledged: {response == self.RESPONSE_OK}")
                return

            # Send metadata
            metadata = {
                'index': 0,
                'event_type': 'block_response',
                'src_path': event['src_path'],
                'block_hash': self.actual_hash,
                'size': len(block_data),
                'packet_count': 1,
                'is_dir': False,
                'status': 'success'
            }
            
            payload = json.dumps(metadata).encode('utf-8')
            header = struct.pack('!I', len(payload))
            message = header + payload
            connection.sendall(message)
            response = connection.recv(3)
            
            if response != self.RESPONSE_OK:
                logging.error("[BLOCK HANDLER] Failed to send metadata")
                return
            
            # Send the actual block data
            block_hash = hashlib.md5(block_data).hexdigest()
            logging.info(f"[BLOCK HANDLER] Sending block data with hash: {block_hash[:8]}")
            
            packet = {
                'index': 1,
                'data': base64.b64encode(block_data).decode(),
                'checksum': block_hash
            }
            
            payload = json.dumps(packet).encode('utf-8')
            header = struct.pack('!I', len(payload))
            message = header + payload
            connection.sendall(message)
            logging.info(f"[BLOCK HANDLER] Sent block data for {block_hash[:8]}")
            
            response = connection.recv(3)
            logging.info(f"[BLOCK HANDLER] Block data acknowledged: {response == self.RESPONSE_OK}")
        except Exception as e:
            logging.error(f"[BLOCK HANDLER] Error sending block data: {e}")


class SyncEvent(Incoming):
    def __init__(self, metadata, address=None, connection=None): # ⬅️ added connection parameter!
        self.metadata = metadata
        super().__init__(address, connection) 

    def apply(self):
        pass
    
    def _get_mac_addr(self, user) -> str:
        for mac_addr in ip_map["users"][user]:
            if mac_addr == str(mac_addr):
                return mac_addr

class CreateDir(SyncEvent):
    def apply(self):
        src_path = self.metadata['src_path']
        os.makedirs(src_path, exist_ok=True)
        logging.info(f"[+] Directory created at: {src_path}")
    
class CreateFile(SyncEvent):
    def apply(self):
        offset = 0
        file_data = b''
        # blocklist = dict()
        packet_count = self.metadata['packet_count']
        logging.info(f"[+] Expecting {packet_count} packets...")

        for index in range(1, packet_count + 1): # Start from 1 to skip metadata packet
            data, hash = self.receive_valid_packet(self.connection, index)
            file_data += data
            # blocklist[hash] = {"offset": offset, "size": len(data)} # data is binary data, hash is checksum
            offset += len(data)

        os.makedirs(os.path.dirname(self.metadata['src_path']), exist_ok=True)
        logging.info(f"[+] Writing file to: {self.metadata['src_path']}")
        with open(self.metadata['src_path'], 'wb') as f:  # Updated to use self.metadata['src_path']
            f.write(file_data)
        logging.info(f"[+] File '{self.metadata['src_path']}' received successfully.")  # Updated to use self.metadata['src_path']

        folder_id = self.metadata['folder_id']
        hash = self.metadata['hash']
        size = self.metadata['size']

        # Verify that the received file's hash matches the metadata hash
        calculated_hash = hashlib.md5(file_data).hexdigest()
        if calculated_hash != hash:
            logging.error(f"[!] Hash mismatch for file {self.metadata['src_path']}. Expected: {hash}, Got: {calculated_hash}")  # Updated to use self.metadata['src_path']
            # Consider whether to reject the file or mark it as corrupted
        else:
            logging.info(f"[+] File hash verified for {self.metadata['src_path']}")  # Updated to use self.metadata['src_path']

        # Create a new file entry in the database
        file_entry = File(
            folder_id=folder_id,
            path=self.metadata['src_path'],  # Updated to use self.metadata['src_path']
            size=size,
            hash=hash,
            version="v1.0"
        )
        
        with app.app_context():
            db.session.add(file_entry)
            db.session.commit()
            logging.info(f"[+] Added file entry to database: {self.metadata['src_path']}")  # Updated to use self.metadata['src_path']

class Delete(SyncEvent):
    def purge_directory(self):
        logging.info(f"[+] Deleting directory and its contents: {self.metadata['src_path']}")
        
        # Use post-order traversal to delete directory contents
        for root, dirs, files in os.walk(self.metadata['src_path'], topdown=False):
            # First delete all files in the current directory
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    logging.info(f"[-] Deleted file: {file_path}")
                    
                    # Delete file entry from database
                    file_entry = session.query(File).filter_by(path=file_path).first()
                    if file_entry:
                        session.delete(file_entry)
                        session.commit()
                except Exception as e:
                    logging.error(f"[!] Error deleting file {file_path}: {e}")
            
            # Then delete the directory itself
            try:
                os.rmdir(root)
                logging.info(f"[-] Deleted directory: {root}")
            except Exception as e:
                logging.error(f"[!] Error deleting directory {root}: {e}")

    def apply(self):
        # TODO check if file or folder
        if self.metadata['is_dir']:
            self.purge_directory()
            logging.info(f"[-] Directory '{self.metadata['src_path']}' deleted successfully.")
        else:
            try:
                os.remove(self.metadata['src_path'])
                logging.info(f"[-] File '{self.metadata['src_path']}' deleted successfully.")
            except FileNotFoundError:
                logging.info(f"[-] File '{self.metadata['src_path']}' already deleted or not found.")
            except Exception as e:
                logging.error(f"[-] Error deleting file '{self.metadata['src_path']}': {e}")

            try:
                with app.app_context():
                    file_entry = session.query(File).filter_by(path=self.metadata['src_path']).first()
                    if file_entry:
                        session.delete(file_entry)
                        session.commit()
                        logging.info(f"[-] File entry for '{self.metadata['src_path']}' deleted from database.")
                    else:
                        logging.info(f"[-] No file entry found for '{self.metadata['src_path']}' in database.")
            except Exception as e:
                with app.app_context():
                    session.rollback()
                logging.error(f"[-] Database error while deleting file entry: {e}")

class Move(SyncEvent):
    
    def apply(self):
        
        # Format source and destination paths
        src_path = self.metadata['src_path']
        dest_path = self.metadata['dest_path']
        
        logging.info(f"[+] Moving from {src_path} to {dest_path}")
        
        if not self.metadata['is_dir']:
            # Handle file move
            try:
                # Create destination directory if needed
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Move the file
                os.replace(src_path, dest_path)
                logging.info(f"[+] File moved from {src_path} to {dest_path}")
                
                # Update database entry
                with app.app_context():
                    # Check if the file entry exists in the database
                    file_entry = session.query(File).filter_by(path=src_path).first()
                    if file_entry:
                        file_entry.path = dest_path
                        session.commit()
                        logging.info(f"[+] Database entry updated for file: {dest_path}")
                    else:
                        logging.warning(f"[!] No database entry found for file: {src_path}")
            except Exception as e:
                logging.error(f"[!] Error moving file: {e}")
        else:
            # Handle directory move
            try:
                # Make sure destination parent exists
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Move the directory
                os.replace(src_path, dest_path)
                logging.info(f"[+] Directory moved from {src_path} to {dest_path}")
                
                # Update folder entry in database
                folder_entry = session.query(Folder).filter_by(path=src_path).first()
                if folder_entry:
                    folder_entry.path = dest_path
                    session.commit()
                    logging.info(f"[+] Database entry updated for folder: {dest_path}")
                
                # Update all file paths in database that were under this directory
                files = session.query(File).all()
                updated_count = 0
                
                for file in files:
                    if file.path.startswith(src_path + '/') or file.path == src_path:
                        new_file_path = file.path.replace(src_path, dest_path, 1)
                        file.path = new_file_path
                        updated_count += 1
                
                if updated_count > 0:
                    session.commit()
                    logging.info(f"[+] Updated {updated_count} file entries in database")
                    
            except Exception as e:
                logging.error(f"[!] Error moving directory: {e}")

class Modify(SyncEvent):
    
    def apply(self):
        offset = 0
        file_data = b''
        # blocklist = dict()
        packet_count = self.metadata['packet_count']
        logging.info(f"[+] Expecting {packet_count} packets...")

        for index in range(1, packet_count + 1): # Start from 1 to skip metadata packet
            data, hash = self.receive_valid_packet(self.connection, index)
            file_data += data
            # blocklist[hash] = {"offset": offset, "size": len(data)} # data is binary data, hash is checksum
            offset += len(data)

        # os.makedirs(os.path.dirname(self.metadata['src_path']), exist_ok=True)
        # logging.info(f"[+] Writing file to: {self.metadata['src_path']}")

        temp_file_path = f"{self.metadata['src_path']}.tmp_{int(time.time())}" #🆗
        logging.info(f"[+] Creating temporary file: {temp_file_path}") #🆗

        with open(temp_file_path, 'wb') as f:
            f.write(file_data)
        logging.info(f"[+] File '{self.metadata['src_path']}' written into {temp_file_path} received successfully.")  # Updated to use self.metadata['src_path']

        # folder_id = self.metadata['folder_id']
        hash = self.metadata['hash']
        size = self.metadata['size']
        version = self.metadata['version']

        # Verify that the received file's hash matches the metadata hash
        calculated_hash = hashlib.md5(file_data).hexdigest()
        if calculated_hash != hash:
            logging.error(f"[!] Hash mismatch for file {self.metadata['src_path']}. Expected: {hash}, Got: {calculated_hash}")  # Updated to use self.metadata['src_path']
            # Consider whether to reject the file or mark it as corrupted
        else:
            logging.info(f"[+] File hash verified for {self.metadata['src_path']}")  # Updated to use self.metadata['src_path']

        # # Create a new file entry in the database
        # file_entry = File(
        #     folder_id=folder_id,
        #     path=self.metadata['src_path'],  # Updated to use self.metadata['src_path']
        #     size=size,
        #     hash=hash,
        #     version=version
        # )
        
        # with app.app_context():
        #     db.session.add(file_entry)
        #     db.session.commit()
        #     logging.info(f"[+] Added file entry to database: {self.metadata['src_path']}")  # Updated to use self.metadata['src_path']


        # TODO Update version
        # TODO copy file to original location
        # TODO delete temp file
        
        file_entry = session.query(File).filter_by(path=self.metadata['src_path']).first()
        file_entry.hash = hash
        file_entry.size = size
        file_entry.version = version
        
        with app.app_context():
            session.commit()
            logging.info(f"[+] Database entry updated for file: {self.metadata['src_path']}")

        os.rename(temp_file_path, self.metadata['src_path'])
        logging.info(f"[+] File: {temp_file_path} moved to original location: {self.metadata['src_path']}")

        os.remove(temp_file_path)
        logging.info(f"[+] Temporary file {temp_file_path} deleted.")

########################################################################################
########################################################################################
########################################################################################
########################################################################################
########################################################################################

if __name__ == "__main__":

    global active_session
    active_session = {}

    dir_file = "dir.json"
    if os.path.exists(dir_file):
        with open(dir_file, "r") as file: # Load data from the file if it exists
            dirs = json.load(file)
    else:
        dirs = {
            # 'C://Users/aryan/Desktop/rebirth': {
            #    'id': 'x2su29dr3', 
            #    'size': 123456,
            #    'type': 'bothways'
        }  

    system = input("windows(w) or linux(l)? ")
    
    if system == "w":
        ip = w_wlan_ip() 
    else: 
        ip = l_wlan_ip()

    print(f"Binding IP: {ip}")

    # Start the listener thread for message listening
    listener_thread = threading.Thread(target=listen_for_messages, daemon=True) # 🧵
    # daemon=True ensures thread exits when main program exits!!
    listener_thread.start()

    # Set up the Flask app with database
    with app.test_request_context("/"):
        request.session = session
        db.create_all()

        global file_to_hash
        file_to_hash = {f.path: f.hash for f in File.query.all()}
        logging.info(f'Loaded file_to_hash with {len(file_to_hash)} entries.')
        logging.info(f'{file_to_hash}')

        # global active_session
        # active_session = {}
        # for key, value in session.items():
        #     active_session[key] = value
        # logging.info(f'active_session dict: {active_session}')

    # Start the Flask server in a separate thread
    flask_thread = threading.Thread(target=run_flask, daemon=True) # 🧵
    flask_thread.start()

    watchdog = threading.Thread(target=start_watchdog, args=(dirs,)) # 🧵
    watchdog.start()

    sync_worker_thread = threading.Thread(target=sync_worker, daemon=True) # 🧵
    sync_worker_thread.start()  # ✅ Start just once

    sync_listener_thread = threading.Thread(target=sync_listener)
    sync_listener_thread.start()
    logging.info("Started sync listener thread")

    # incoming_handler = Incoming()
    # block_request_thread = threading.Thread(target=incoming_handler.listen_for_requests, daemon=True)
    # block_request_thread.start()
    # logging.info("Started block request listener thread")

    socketio.run(app)
    # socketio.run(app, debug=True, host='0.0.0.0')