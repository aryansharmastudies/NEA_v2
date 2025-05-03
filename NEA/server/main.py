from sqlalchemy import URL, create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
import socket
import json
import logging
import re
import os
import asyncio
from get_wip import *
from get_lip import *
from sqlalchemy.orm import sessionmaker

import struct
import base64
import hashlib
import threading
import shutil
import time
import queue
import uuid
from datetime import timedelta
from datetime import datetime


################################################################################
################################################################################
################################################################################
################################################################################
################################################################################


sync_active = threading.Event()
sync_active.clear()  # Sync is paused initially


################################################################################
################################################################################
################################################################################
################################################################################
################################################################################



########## LOGGING ##############################
def log() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='basic.log',)
log()
########## IP ADDRESS ############################
# NOTE - gets the ip. hash the one you don't want.
system = input('windows(w) or linux(l)?')
if system == 'w':
    ip = w_wlan_ip()
else:
    ip = l_wlan_ip()
logging.info(ip)
########## DATA BASE #############################
db_url = 'sqlite:///database/database.db'
engine = create_engine(db_url)
Base = declarative_base()

Session = sessionmaker(bind=engine)
session = Session() # returns Session object upon which we can perform action.

class User(Base):
    __tablename__ = 'users'

    user_id = Column(Integer, primary_key=True)
    name = Column(String)
    hash= Column(String)
    email = Column(String)

class Device(Base):
    __tablename__ = 'devices'

    user_id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String)
    mac_addr = Column(String, primary_key=True)

class Folder(Base):
    __tablename__ = 'folders'

    mac_addr = Column(String)
    folder_id = Column(String, primary_key=True)
    name = Column(String)
    mac_addr = Column(String)
    path = Column(String)
    type = Column(String)
    size = Column(Integer)

class Share(Base):
    __tablename__ = 'share'
    
    username = Column(String, primary_key=True)
    folder_id = Column(String, primary_key=True)
    mac_addr = Column(String, primary_key=True)
    folder_label = Column(String)
    path = Column(String)

class File(Base):
    __tablename__ = 'files'

    folder_id = Column(String)
    path = Column(String, primary_key=True, index=True)
    size = Column(Integer)
    hash = Column(String)
    version = Column(String)
    block_list = Column(String)

Base.metadata.create_all(engine)

# RESPONSE CLASS
class Response: # 👑
    def __init__(self):
        #self.client_data = ''
        #self.status = ''
        #self.status_msg = ''
        pass
    
    def tojson(self):
        return json.dumps(self,default=lambda o: o.__dict__, sort_keys=True, indent=2)

class Status_Response(Response):
    def __init__(self):
        super().__init__()
        logging.info(f'Status_Response Object is made')

class Data_Response(Response):
    def __init__(self, requested_data):
        super().__init__()
        self.requested_data = requested_data # e.g. {'users': {'user_id': None, 'name': None}, 'devices': {'user_id': None, 'name': None}}
        self.data = dict() # using a dictionary to store scraped data
        logging.info(f'Data_Response Object is made')
    
    def scrape(self): # used to scrape the database for requested data
        for table_name in self.requested_data: # iteratively goes through each requested table!
            scraped_data = self.scrape_db(table_name, self.requested_data[table_name]) 
            self.data[table_name] = scraped_data # scraped_data should be a list returned back!
        logging.info(f'scraped data to be returned!: {self.data}')
    
    ########## CRUD(create, read, update, delete) #################
    def scrape_db(self, table_name, attributes_dict): # scrapes db and returns back data
        # input: ('devices', {'user_id': None, 'name': None})
        # or: ('folders', {'mac_addr': 'some_mac_addr', 'folder_id': None, 'name': None, 'path': None, 'type': None})
        
        # Map the table name to the corresponding SQLAlchemy model
        table_map = {
            'users': User,
            'devices': Device,
            'folders': Folder,
            'share': Share,
            'files': File
            # Add other tables here as needed 
        }
        
        # Get the SQLAlchemy model for the table
        table_model = table_map.get(table_name)
        if not table_model:
            logging.warning(f"Table '{table_name}' not found in table_map.")
            return []
        
        # Get the attribute names that we want to return
        attributes = list(attributes_dict.keys())
        
        # Build the query with the requested attributes
        query = session.query(*[getattr(table_model, attr) for attr in attributes])
        
        # Add filters for attributes with non-None values
        filters = []
        for attr, value in attributes_dict.items():
            if value is not None:
                filters.append(getattr(table_model, attr) == value)
        
        if filters:
            query = query.filter(*filters)
        
        # Execute the query
        results = query.all()
        
        # Convert the results into a list of dictionaries for easier access
        scraped_data = []
        for row in results:
            row_dict = {}
            for i, attr in enumerate(attributes):
                row_dict[attr] = row[i]
            scraped_data.append(row_dict)
        
        logging.info(f"Scraped {len(scraped_data)} records from {table_name}")
        return scraped_data

class Instruction_Response(Response):
    def __init__(self):
        super().__init__()
        logging.info(f'Instruction_Response Object is made')

class Blockdata_Response(Response):
    def __init__(self):
        super().__init__()
        logging.info(f'Blockdata_Response Object is made')


def create_user(r_user, hash):
    user = User(name=r_user, hash=hash, email='default')
    if session.query(User).filter_by(name=r_user).first():
        logging.info(f'User: {r_user} already exists')
        return json.dumps({'status': '409', 'status_msg': 'User already exists'})
    else: 
        logging.info(f'Creating user: {r_user} with hash: {hash}')
        session.add(user)
        session.commit()
        return json.dumps({'status': '201', 'status_msg': 'User created successfully'})

def login(l_user, hash):
    user = session.query(User).filter_by(name=l_user).first()
    if user:
        if user.hash == hash:
            logging.info(f'User: {l_user} has logged in')
            return json.dumps({'status': '200', 'status_msg': 'Login successful'})
        else:
            logging.info(f'Unauthorized access attempt for user: {l_user}')
            return json.dumps({'status': '401', 'status_msg': 'Retry with correct password'})
    else:
        logging.info(f'User: {l_user} not found')
        return json.dumps({'status': '404', 'status_msg': 'User not found'})
    
def create_device(username, name, mac_addr):
     # NOTE: username will be passed in by the user, when adding a new device which will map to user_id when adding device.
    user_id = session.query(User).filter_by(name=username).first().user_id
    logging.info(f'User_ID: {user_id}')
    for device in session.query(Device).filter_by(user_id=user_id):
        logging.info(f'Comparing: {name} with Mac_addr: {mac_addr} WITH Device: {device.name} with Mac_addr: {device.mac_addr}')
        if device.mac_addr == str(mac_addr):
            logging.info(f'Device Mac_addr: {mac_addr} already exists for User: {username}')
            return json.dumps({'status': '409', 'status_msg': 'Device with this MAC address already exists'})
        elif device.name == name:
            logging.info(f'Device name: {name} already exist for User: {username}')
            return json.dumps({'status': '409', 'status_msg': f'Device with name: {name} already exists'})
    logging.info(f'Adding device: {name} with Mac_addr: {mac_addr} for User: {username} with User_ID: {user_id}')
    device = Device(user_id=user_id, name=name, mac_addr=mac_addr)
    session.add(device)
    session.commit()
    return json.dumps({'status': '201', 'status_msg': 'Device added successfully'})

'''
class Folder(Base):
    __tablename__ = 'folders'

    folder_id = Column(String, primary_key=True)
    name = Column(String)
    mac_addr = Column(String)
    path = Column(String)
    type = Column(String)
    size = Column(Integer)


class Share(Base):
    __tablename__ = 'share'
    
    folder_id = Column(String, primary_key=True)
    mac_addr = Column(String, primary_key=True)
    path = Column(String)
'''

# {'action': 'add_folder', 'name': "anjali's folder", 'directory': '~/HqZYgro3ux',
#  'shared_users': ['admin:x230', 'admin:admins_MBP', 'joel:joels_pixel'], 'folder_type': 'sync_bothways'}

def create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type, owner_username):
    # DONE check if folder_id exists!
    # DONE convert windows path to linux! USE REGEX!
    # TODO share it to all users... :<
    for folder in session.query(Folder):
        if folder.folder_id == str(folder_id):
            logging.info(f'[F] Folder_id: {folder_id} already exists!')
            return json.dumps({'status': '409', 'status_msg': 'Folder with this folder_id already exists'})
    
    result = validate_directory(directory)
    if result == '400':
        return json.dumps({'status': '400', 'status_msg': 'Invalid directory format'})


    # DONE find username given mac_addr of host
    # mac_addr -> user_id -> username
    host_name = owner_username
    host_id = session.query(User).filter_by(name=host_name).first().user_id
    # host_id = session.query(Device).filter_by(mac_addr=mac_addr).first().user_id
    # hostname = session.query(User).filter_by(user_id=host_id).first().name
    logging.info(f'[F] 👤Host: {host_name} with User_ID: {host_id} is creating folder📂: {folder_label} with folder_id: {folder_id} in directory: {directory}')

    for shared_user in shared_users:  # 😳😿
        # find the shared_user and its devices MAC ADDRESS
        # check if it exists in ip_map.json
        # then send a ping first
        # then followed by a request, if pong is returned

        shared_user = shared_user.split(':') # ['admin', 'x230']
        username = shared_user[0] # 🌸
        device_name = shared_user[1] # 🌸
        user = session.query(User).filter_by(name=username).first() # 🌸
        target_user_id = user.user_id # 🌸

        if not user:
            logging.info(f'[F] User: {username} not found')
            return json.dumps({'status': '404', 'status_msg': 'User not found'})
        
        logging.info(f'[F] User: {username} found with User_ID: {target_user_id}')
        device = session.query(Device).filter_by(user_id=target_user_id, name=device_name).first() # 🌸
        
        if not device:
            logging.info(f'[F] Device: {device_name} not found for User: {username}')
            return json.dumps({'status': '404', 'status_msg': 'Device not found'})
        
        device_mac_addr = device.mac_addr # gets devices mac addr # 🌸
        logging.info(f'[F] Device: {device_name} found with Mac_addr: {device_mac_addr}')

        if username not in ip_map["users"]:
            logging.info(f'[F] User: {username} not found in ip_map')
            return json.dumps({'status': '404', 'status_msg': 'User not found in ip_map'})

        logging.info(f'[F] {ip_map["users"][username]}')        
        if str(device_mac_addr) not in ip_map["users"][username]:
            logging.info(f'Device: {device_name} not found in ip_map')
            return json.dumps({'status': '404', 'status_msg': 'Device not found in ip_map'})
        
        # logging.info(f'ip of device: {ip_map["users"][username][device_mac_addr]}')
        # ip = ip_map["users"][username][device_mac_addr] # gets users ip address
        
        # logging.info(f'Sending authorisation request to {username}, device: {device.name}, mac_addr: {device_mac_addr},  ip: {ip}')
        # status = send(json.dumps({'action': 'authorise', 'user': username}), ip, 6000) # sends a ping through!
        # logging.info(f'User Status: {status} (400/404 -> failed, 200 -> success)')
        # # either no response -> add to list of invites!!
        # # or another user is online(from same ip - maybe ip changed/user logged into device)
        # # or correct user is online
        # if status == '400' or status == '404': # if request fails
        #     logging.info(f'Authorisation failed for {username} with ip: {ip}')
            # adds to invites.json

        logging.info(f'[F] invites.json BEFORE adding: {invites}')
        if username not in invites["folders"]: # first check if the user is in the invites file 🌸
            invites["folders"][username] = {} # 🌸
            invites["folders"][username][device_mac_addr] = [] # if not, add them 🌸
        elif device_mac_addr not in invites["folders"][username]: # then check if the device is in the invites file 🌸
            invites["folders"][username][device_mac_addr] = [] # if not, add it 🌸

        invites["folders"][username][device_mac_addr].append([folder_label, folder_id, host_name])# ✅ ADD THE HOST WHO IS SENDING INVITE! 🌸
        logging.info(f'[F] invites.json AFTER adding: {invites}')
        with open(invites_file, "w") as file:
            json.dump(invites, file, indent=2)
        # everytime user logs in, check if they are in the invites file!!

        # ❗no need to return if user is offline, as the user will get the invite when they log in.
        # return json.dumps({'status': '400', 'status_msg': 'Ping failed'})

    # /home/aryan/desktop/python/client.txt
    server_directory = directory.split('/')# [home aryan desktop python client.txt]

    server_directory[0] = str('~') # insert user_id
    server_directory[1] = str(host_id) # insert user_id
    server_directory[2] = str(mac_addr) # insert mac_addr
    server_directory = '/'.join(server_directory)
    server_directory = os.path.expanduser(server_directory) # expands the ~ to the home directory of the user.
    logging.info(f'[F] Creating folder directory: {server_directory}')
    
    try: 
        os.makedirs(server_directory)
        logging.info(f'[F] Directory {server_directory} created successfully.')
    except FileExistsError:
        logging.info(f'[F] ⚠️ Directory {server_directory} already exists, skipping creation.')

    # NOTE: ADD TO DB ONLY AFTER DIRECTORY PATH IS FORMATTED CORRECTLY! AND DIRECTORY IS CREATED!
    try: 
        logging.info(f'[F] Adding folder entry to database for folder_id: {folder_id}, mac_addr: {mac_addr}')
        folder = Folder(mac_addr=mac_addr, name=folder_label, folder_id=folder_id, path=server_directory, type=folder_type)
        session.add(folder)
        session.commit()
        logging.info(f"[F] New folder entry created for folder_id: {folder_id}, mac_addr: {mac_addr}")
    except Exception as e:
        session.rollback()
        logging.error(f"[F] Error adding folder entry: {e}")
        return json.dumps({'status': '500', 'status_msg': f'Database error: {str(e)}'})

    new_share = Share(
        username=owner_username,
        folder_id=folder_id,
        mac_addr=mac_addr,
        folder_label=folder_label,
        path=directory
    )

    try:
        logging.info(f'[F] Creating new share for folder_id: {folder_id}, mac_addr: {mac_addr}, user: {owner_username}')    
        session.add(new_share)
        session.commit()
        logging.info(f"[F] New share entry created for folder_id: {folder_id}, mac_addr: {mac_addr}")
    except Exception as e:
        session.rollback()
        logging.error(f"[F] Error adding share entry: {e}")
        return json.dumps({'status': '500', 'status_msg': f'Database error: {str(e)}'})
    
    return json.dumps({'status': '201', 'status_msg': 'Folder added successfully'})

def validate_directory(directory): # NOTE need this for checking if directory is either valid unix or windows. if windows -> convert to unix.
        # Check if the directory is in Unix format
    unix_format_check = re.search(r'(/.+)*', directory)
    # Check if the directory is in Windows format
    windows_format_check = re.search(r'^C:\\Users\\.+', directory)
    
    # Log the results of the checks
    if unix_format_check:
        logging.info(f"Unix format directory: {directory}")
        return directory
    elif windows_format_check:
        logging.info(f"Windows format directory: {directory}")
        directory = directory.split('\\')
        directory = directory[3:]
        directory = '~\\' + '\\'.join(directory)
        logging.info(f'Windows directory converted to Unix: {directory}')
        return directory
    else:
        logging.info(f"Invalid directory format: {directory}")
        return '400'

                                                                                                                                                                                                                                                                                                                                   
def track_ip(user, mac_addr, ip): # DONE if user logs in with differnet ip from same device! it should update it.
    if user not in ip_map["users"]:
        ip_map["users"][user] = {}
    mac_addr = str(mac_addr)
    ip_map["users"][user][mac_addr] = ip # if user signs in with differet ip from same device -> it overwrites the ip. 
    logging.info(f'ip_map: {ip_map}')

    with open(ip_file, "w") as file:
        json.dump(ip_map, file, indent=2)
    
    return json.dumps({'status': '200', 'status_msg': 'IP updated successfully'})
        

def alert(user, mac_addr): # TODO make it send back any unanswered invites to the user
    user = str(user)
    mac_addr = str(mac_addr)
    logging.info(f'building alerts for {user} with mac_addr {mac_addr}')
    alerts = []
    if user in invites["folders"]:
        if mac_addr in invites["folders"][user]:
            for invite in invites["folders"][user][mac_addr]:
                logging.info(f'user\'s invite: {invite}')
                alerts.append(invite)
                logging.info(f'building alerts: {alerts}')
    if user in invites["groups"]:
        if mac_addr in invites["groups"][user]:
            for invite in invites["groups"][user][mac_addr]:
                alerts.append(invite)
    logging.info(f'sending alerts to {user} with mac_addr {mac_addr}: {alerts}')
    return alerts


def accept_share(client_data, clientsocket):
    try:
        folder_id = client_data.get('folder_id')
        folder_label = client_data.get('folder_label')
        directory = client_data.get('directory')
        mac_addr = client_data.get('mac_addr')
        username = client_data.get('username')
        
        logging.info(f"Processing share acceptance for folder_id: {folder_id}, from device: {mac_addr}, username: {username}")
        
        # Check if entry already exists to avoid duplicates
        existing_share = session.query(Share).filter_by(username=username, folder_id=folder_id, mac_addr=mac_addr).first()
        
        if existing_share:
            logging.info(f"Share entry already exists for folder_id: {folder_id}, mac_addr: {mac_addr}")
            # Even if share exists, we should still sync the folder
            response = json.dumps({'status': '409', 'status_msg': 'Share already exists'})
        
        else:
            folder = session.query(Folder).filter_by(folder_id=folder_id).first()
            if folder.type == 'sync_bothways':
                response = json.dumps({'status': '201', 'status_msg': 'Share accepted successfully', 'folder_type': folder.type})
            else:
                response = json.dumps({'status': '201', 'status_msg': 'Share accepted successfully', 'folder_type' : folder.type})
            clientsocket.send(str(response).encode('utf-8'))
            logging.info(f"sent response: {json.loads(response)}")

            new_share = Share(
                username=username,
                folder_id=folder_id,
                mac_addr=mac_addr,
                folder_label=folder_label,
                path=directory
            )
            
            # Add to database
            session.add(new_share)
            logging.info(f"New share entry created for folder_id: {folder_id}, mac_addr: {mac_addr}")
            
            # Clean up invites.json
            if username and username in invites['folders']:
                if str(mac_addr) in invites['folders'][username]:
                    # Remove the accepted invite
                    invites_to_keep = []
                    for invite in invites['folders'][username][str(mac_addr)]:
                        if invite[1] != folder_id:
                            invites_to_keep.append(invite)
                    
                    invites['folders'][username][str(mac_addr)] = invites_to_keep
                    
                    # Save updated invites
                    with open(invites_file, "w") as file:
                        json.dump(invites, file, indent=2)
                    logging.info(f"Removed accepted invite for folder_id: {folder_id} from user: {username}")
            
            try:
                session.commit()
                logging.info(f"Share entry added successfully for folder_id: {folder_id}, mac_addr: {mac_addr}")
                response = json.dumps({'status': '201', 'status_msg': 'Share accepted successfully'})
            except Exception as e:
                session.rollback()
                logging.error(f"Error adding share entry: {e}")
                response = json.dumps({'status': '500', 'status_msg': f'Database error: {str(e)}'})
        
    except Exception as e:
        logging.error(f"Error processing share acceptance: {e}")
        response = json.dumps({'status': '400', 'status_msg': f'Error processing request: {str(e)}'})
        # return response

    # TODO send folder!

    # client2 is ONLINE
    # folder path to traverse
    # username, mac_address to send it to.
    '''
        self.src_path = event['src_path']
        self.is_dir = event['is_dir']
        self.origin = event['origin']
        self.event_type = event['event_type']
        self.folder_id = event.get('folder_id')
    '''

    root_folder = session.query(Folder).filter_by(folder_id=folder_id).first()
    logging.info(f'root_folder: {root_folder}')
    root_folder_path = root_folder.path
    logging.info(f'root_folder_path: {root_folder_path} to be traversed...')

    event = {
        'folder_id' : folder_id,
        'src_path' : root_folder_path,
        'is_dir' : False,
        'event_type' : 'Initialise',
        'origin' : 'accept_share'
    }

    # outgoingsock = socket.socket() 
    # outgoingsock.connect((ip_map["users"][username][str(mac_addr)], 6969))
    copy = Outgoing(event)
    copy.initialise_copy(directory, root_folder_path, folder_id, folder_label, username, mac_addr)

def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

########## SOCKETS ###############################
def send(message, ip, port): 
    logging.info(f'Sending: {message} to {ip} on port {port}')
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        c.connect((ip, port))
        c.send(message.encode('utf-8'))
        client_data = c.recv(1024).decode('utf-8')
        logging.info(f'client_data: {client_data}')
        client_data = json.loads(client_data)
        
        status_code = client_data.get('status_code', '400')
        status_msg = client_data.get('status_msg', False)
        data = client_data.get('data', False)
    except:
        return '400' 

    if json.loads(message)['action'] == 'authorise':
        return status_code



def handle_client_message(clientsocket, message):
    #NOTE 'status' here includes both the status-code and status-description e.g. 
    # {'status': '201', 'status_msg': 'Device added successfully'}
    try:
        client_data = json.loads(message)  # Parse JSON message
        action = client_data.get('action')
    except json.JSONDecodeError:
        logging.info('Invalid JSON received.')
    except KeyError as e:
        logging.info(f'Missing field: {e}')

    if action == 'ping':
        logging.info(f'Received ping from {client_data['ip_addr']}')
        clientsocket.send('pong'.encode('utf-8'))
        logging.info(f'Pong sent to {client_data['ip_addr']}')

    elif action == 'track': # client sends this thru whenever they are redirected to 'dashboard.html'
        ip_addr = client_data['ip_addr']
        user = client_data['user']
        mac_addr = client_data['mac_addr']
        logging.info(f'Recieved tracking info from {user} with ip_addr {ip_addr} and mac_addr {mac_addr}')
        response = json.loads(track_ip(user, mac_addr, ip_addr)) # ok we track them. but we should also respond back with any notifications/updates.    
        '''w
            issue may arise when a user1 tries to invite another user2 device which user2 has not yet registered.
            ACTUALLY, it will not happen, since user1 can only invite anyone else whose device is registered!
            the server only sends back registered device to user1!
        '''
        # 😋 data is {'status': '200', 'status_msg': 'IP updated successfully'}
        alerts = alert(user, mac_addr)
        response['data'] = alerts
        response = json.dumps(response)
        # 😋 data is {'status': '200', 'status_msg': 'IP updated successfully', 'alerts': []}
        logging.info(f'Sending tracking results + alerts: {response}')
        clientsocket.send(str(response).encode('utf-8'))


        to_remove = []
        try: 
            for index, pending_event in enumerate(sync_list[user][mac_addr]):

                pending_sync = SyncEvent(pending_event)
                pending_sync.echo()
                to_remove.append(index)
            
            for index in reversed(to_remove):
                sync_list[user][mac_addr].pop(index)
        except Exception as e:
            logging.info(f'Error in sync_list {e}')
            pass

    elif action == 'login':
        l_user = client_data['l_user']
        hash = client_data['hash']
        status = login(l_user, hash)
        logging.info(f'Sending login status: {status}')
        clientsocket.send(str(status).encode('utf-8'))
        
    elif action == 'register_user':
        r_user = client_data['r_user']
        hash = client_data['hash']
        status = create_user(r_user, hash)
        logging.info(f'Sending registration status: {status}')
        clientsocket.send(str(status).encode('utf-8'))
    
    elif action == 'add_device':
        mac_addr = client_data['mac_addr']
        device_name = client_data['r_dev_name']
        username = client_data['user']
        status = create_device(username, device_name, mac_addr)
        logging.info(f'Sending device status: {status}')
        clientsocket.send(str(status).encode('utf-8'))
        #TODO after adding device in db, then tracker the ip and mac addr!


# {'action': 'add_folder', 'folder_label': 'feetpics', 'folder_id': 'nSBSsJLXcs', 'directory': '~/nSBSsJLXcs', 'shared_users': ['aryan:MBP'], 'folder_type': 'sync_bothways', 'mac_addr': 167132875827157}
    elif action == 'add_folder': # TODO get it working.
        logging.info(f'Recieved data to add folder: {client_data}')
        mac_addr = client_data['mac_addr'] # of the user sharing it.
        folder_label = client_data['folder_label']
        folder_id = client_data['folder_id']
        directory = client_data['directory']
        shared_users = client_data['shared_users']
        folder_type = client_data['folder_type']
        owner_username = client_data['user']
        status = create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type, owner_username)
        logging.info(f'Sending folder status: {status}')
        clientsocket.send(str(status).encode('utf-8'))

    elif action == 'remove_user': # TODO should be a potential option for admin.
        username = client_data['username']
        logging.info(f'Removing user: {username}')
        # Remove user logic here

    elif action == 'request':
        # {'action': 'request', 'data': {'users': ['user_id', 'name'], 'devices': ['user_id', 'name']}}
        requested_data = client_data['data']
        response = Data_Response(requested_data) # response is the object made.
        response.scrape()
        response_in_json = response.tojson()
        logging.info(f'SENDING: {response_in_json}')
        clientsocket.send(str(response_in_json).encode('utf-8')) # converted to JSON using 'tojson'.
        del response

    elif action == 'invite_response':
        invite_type = client_data('invite_type') # can be either a group or folder invite response
        data = client_data('data')
        '''
            could include (folder_id, mac_addr and user_directory) if folder response
            otherwise would include a 'accept' or 'decline' as well as 'user_id' and 'group_id' for group invite response
        '''
        pass
    
    elif action =='accept_share':
        response = accept_share(client_data, clientsocket)
        logging.info(f'Accepting share: {response}')
        # clientsocket.send(str(response).encode('utf-8'))
        
    else:
        logging.info('Unknown action!')
    

# SERVER LOOP

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 8000))
    s.listen(10)

    while True:
        clientsocket, address = s.accept() # if client does s.connect((server_name, 8000))
        logging.info(f'Connection from {address} has been established!')
        # Receive data
        message = clientsocket.recv(1024).decode('utf-8')
        logging.info(f'message: {message}')
        handle_client_message(clientsocket, message)
        
        clientsocket.close()

# NOTE if sending and receiving data dont work concurrently, use THREADS/asyncio

def sync_worker(): # bridges barrier between incoming data and sync class
    incomingsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    incomingsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    incomingsock.bind((ip, 9696))
    logging.info(f"[+] Listening on {ip}:9696...")
    incomingsock.listen(1) # only can recieve data from one client at a time otherwise, it can get messy.

    while True:
        connection, address = incomingsock.accept() # if client does s.connect((server_name, 8000))
        logging.info(f'Connection from {address} has been established!')
        sync_job = Incoming(address, connection)
        logging.info(f"[+] Sync job created for {address}...")
        sync_job.receive_metadata()
        logging.info(f"[+] Sync job completed for {address}...")
        connection.close()
        logging.info(f"[-] Connection closed for {address}...")
        del sync_job
        logging.info(f"[-] Sync job deleted for {address}...")

class Sync:
    def __init__(self):
        self.BLOCK_SIZE = 1024
        self.HEADER_SIZE = 4
        self.RESPONSE_OK = b'ACK'
        self.RESPONSE_ERR = b'ERR'

class Incoming(Sync):
    def __init__(self, address=None, connection=None):
        super().__init__()
        self.PORT = 9696
        self.connection = connection
        self.address = address
        
    def recv_exact(self, connection: socket.socket, num_bytes: int) -> bytes:
        """Receive an exact number of bytes from the socket."""
        if connection is None:
            raise ValueError("Connection object is None. Make sure a valid socket connection is passed.")
        
        data = b''
        while len(data) < num_bytes:
            packet = connection.recv(num_bytes - len(data))
            # logging.info(f"[+] Packet received: {packet}") # 🔔
            if not packet:
                raise ConnectionError("Connection closed prematurely")
            data += packet
        return data

    def receive_valid_packet(self, connection: socket.socket, index: int) -> bytes:
        """Receive and validate a packet until the checksum matches."""
        while True: # using while loop so we can retry
            header = self.recv_exact(connection, self.HEADER_SIZE)
            payload_length = struct.unpack('!I', header)[0]
            # logging.info(f"[+] Packet: {index} | Payload length: {payload_length}") # 🔔
            payload = self.recv_exact(connection, payload_length)
            payload = json.loads(payload.decode())
            # logging.info(f"[+] Packet: {index} | Payload received: {payload}") # 🔔

            if index == 0: # if its metadata!
                connection.send(self.RESPONSE_OK)
                metadata = payload
                return metadata
            
            if index == 'blocklist':
                connection.send(self.RESPONSE_OK)
                return payload
            
            decoded_data = base64.b64decode(payload['data']) # DECODE FROM BASE64 TO BINARY
            checksum = payload['checksum']

            actual_checksum = hashlib.md5(decoded_data).hexdigest() # CHECKING TO SEE INTEGRITY OF THE DATA
            if actual_checksum == checksum:
                connection.send(self.RESPONSE_OK)
                # logging.info(f"[+] Packet {index} received and verified.") # 🔔
                return decoded_data, actual_checksum # SENDING BACK DATA AND HASH/CHECKSUM
            else:
                connection.send(self.RESPONSE_ERR)
                logging.info(f"[!] Checksum mismatch on packet {index}. Retrying...")

    def receive_metadata(self) -> None:
        metadata = self.receive_valid_packet(self.connection, 0)
        logging.info(f"[+] Metadata received: {metadata}")
        event_type = metadata['event_type']
        # TODO CHECK IF ITS DIRECTORY OR FILE
        
        if metadata['is_dir'] and event_type == 'created':
            logging.info(f"[+] Initiating CreateDir.apply()")
            CreateDir(metadata, self.address).apply() # ↙️
            
        elif not metadata['is_dir'] and event_type == 'created': # i.e. a file is created
            logging.info(f"[+] Initiating CreateFile.apply()")
            CreateFile(metadata, self.address, self.connection).apply() # ↙️
            
        elif event_type == 'deleted':
            logging.info(f"[+] Initiating Delete.apply()")
            Delete(metadata, self.address).apply() # ↙️
            
        elif event_type == 'moved':
            logging.info(f"[+] Initiating Move.apply()")
            Move(metadata, self.address).apply() # ↙️
            
        elif event_type == 'modified':
            logging.info(f"[+] Initiating Modify.apply()")
            Modify(metadata, self.address, self.connection).apply() # ↙️
            
        elif event_type == 'block_response':
            logging.info(f"[+] Initiating Block.apply() with self.address: {self.address} and connection: {self.connection}")
            block_data, actual_hash = Block(metadata, self.address, self.connection).apply() # ↙️
            logging.info(f"[+] Block data received! Actual hash of Block Data: {actual_hash}")
            return block_data, actual_hash

class SyncEvent(Incoming):
    def __init__(self, metadata, address=None, connection=None): # ⬅️ added connection parameter!
        self.metadata = metadata
        super().__init__(address, connection) 

    def apply(self):
        pass

    def handle_global_blocklist(self, action: str, blocklist: dict = None, hashlist: list = None, src_path: str = None, dest_path: str = None, query = None) -> None:
        # action could be 'add' 'delete' 'move' 'query'!
        # blocklist only sent if action is 'add' or 'delete'
        Global_Blocklist(action=action, blocklist=blocklist, hashlist=hashlist, src_path=src_path, dest_path=dest_path, query=query)
        # action='add' blocklist=[{'hash1':{'offset':offset, 'size':size}}, {'hash2':{'offset':offset, 'size':size}}] src_path='/home/...'
        # action='delete' delete that block as well as all instances of it. send: src_path='/home/...' + hashlist(list of hashes to be deleted!)
        # action='move' renames source path of file for specified hash. e.g. {'hash1':{'src_path':'/home/file.txt', ...}} -> {'hash1':{'src_path':'/home/FILE.txt', ...}} 
        # action='query' asks back file data in binary for hash specified!

    def _persist_queue(self):
        try:
            all_events = list(sync_queue.queue)
            with open("sync_queue.json", "w") as f:
                json.dump(all_events, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to persist sync queue: {e}")


    def persist_sync_list(self):
        try:
            with open("sync_list.json", "w") as f:
                json.dump(sync_list, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to persist sync list: {e}")

    def _get_mac_addr(self, user) -> str:
        for mac_addr in ip_map["users"][user]:
            if mac_addr == str(mac_addr):
                return mac_addr
            
    def format_path(self, path) -> str:

        # DONE remove client's local root directory e.g. '/home/aryan/'
        # DONE replace it with owners directory e.g. '/home/pi/02/123123/'

        remove_prefix = session.query(Share).filter_by(folder_id=self.metadata['folder_id'], username=self.metadata['user']).first().path
        new_prefix = session.query(Folder).filter_by(folder_id=self.metadata['folder_id']).first().path

        # Remove the old prefix and add the new one
        if path.startswith(remove_prefix):
            relative_path = path[len(remove_prefix):]  # Get the path after the prefix
            updated_path = new_prefix + relative_path
            logging.info(f"[F] Formatted Path: {updated_path}")
        else:
            logging.info("Prefix not found in path")
        return updated_path

    def echo(self): # sends event/data to client2 OR if client2 offline, adds to sync_queue 🔊🔊🔊
        sender_user = self.metadata['user']
        logging.info(f"[+] User: {sender_user}")
        folder_id = self.metadata.get('folder_id')
        logging.info(f"[+] Folder ID: {folder_id}")
        event_type = self.metadata.get('event_type')
        logging.info(f"[+] Event type: {event_type}")
        is_dir = self.metadata.get('is_dir')
        logging.info(f"[+] Is directory: {is_dir}")
        root_folder = session.query(Folder).filter_by(folder_id=folder_id).first()
        logging.info(f"[+] Folder we got from table: {root_folder}")
        formatted_src_path = self.format_path(self.metadata['src_path']) # /home/kyoto/Documents/Shared/Wallpaper/Nature becomes /home/pi/02/123123/Documents/Shared/Wallpaper/Nature
        logging.info(f"[+] Formatted path: {formatted_src_path}")
        if event_type == 'moved':
            formatted_dest_path = self.format_path(self.metadata['dest_path'])
            logging.info(f"[+] Formatted Destination path: {formatted_dest_path}")
            try: 
                dest_path = os.path.relpath(formatted_dest_path, root_folder.path) # root_folder.path gives /home/pi/02/123123/Documents/Shared/Wallpaper
                logging.info(f"Calculated relative dest path: {dest_path}")

            except ValueError as e:
                # Handle case where paths are on different drives (Windows)
                logging.error(f"Error calculating relative path: {e}")
                src_path = formatted_src_path  # Fallback to using the full path
        try:
            # Get the relative path from folder.path to formatted_src_path
            src_path = os.path.relpath(formatted_src_path, root_folder.path) # root_folder.path gives /home/pi/02/123123/Documents/Shared/Wallpaper
            # so you end up getting /Nature
            logging.info(f"Calculated relative src path: {src_path}")
        except ValueError as e:
            # Handle case where paths are on different drives (Windows)
            logging.error(f"Error calculating relative path: {e}")
            src_path = formatted_src_path  # Fallback to using the full path

        shared_users = session.query(Share).filter(
            Share.folder_id == folder_id,
            Share.username != sender_user
        ).all()

        for user in shared_users:
            src_path = user.path + '/' + src_path
            new_metadata = self.metadata
            new_metadata['src_path'] = src_path
            new_metadata['local_path'] = formatted_src_path
            logging.info(f"[+] Users src path: {src_path}")

            if event_type == 'moved':
                dest_path = user.path + '/' + dest_path
                new_metadata['dest_path'] = dest_path
                logging.info(f"[+] Users dest path: {dest_path}")

            logging.info(f"[+] Sending event {event_type} to {user.mac_addr} to src_path: {src_path}")
            # just forward that metadata to client.
            ip_addr = ip_map["users"][user.username][user.mac_addr]
            logging.info(f"[+] IP address of {user.username}: {ip_addr}")
            try: 
                # TODO bind to client
                outgoingsock = socket.socket()
                outgoingsock.connect((ip_addr, 6969))
                logging.info(f"[+] Connected to {user.mac_addr} at {ip_addr}")
                echo_event = Outgoing(new_metadata) # OUTGOING OBJECT
                logging.info(f"[+] Created new Outgoing object - echo_event")
                echo_event.OG_send_packet(outgoingsock, new_metadata)
                logging.info(f"[+] metadata packet sent to {user.mac_addr} at {ip_addr}")

                if event_type in ['created', 'modified'] and is_dir == False:
                    # echo_event.create_packet(formatted_path)
                    for packet in echo_event.packets:
                        echo_event.send_packet(outgoingsock, packet)

                outgoingsock.close()
                pass
            
            except socket.error as e:
                logging.error(f"[!] Failed to send event to {user.mac_addr} at {ip_addr}: {e}") 
                logging.info(f"[!] Client {user.mac_addr} is offline. Adding to sync queue.")
                if user.username not in sync_list:
                    sync_list[user.username] = {}
                if user.mac_addr not in sync_list[user.username]:
                    sync_list[user.username][user.mac_addr] = []
                sync_list[user.username][user.mac_addr].append(new_metadata)
                
                self.persist_sync_list()

class CreateDir(SyncEvent):

    def apply(self):
        formatted_path = self.format_path()
        os.makedirs(formatted_path, exist_ok=True)
        logging.info(f"[+] Directory created at: {formatted_path}")
        
        # Get folder_id from metadata or path
        folder_id = self.metadata.get('folder_id')
        if not folder_id:
            # Try to extract folder_id from the path
            parent_folder = session.query(Folder).filter_by(path=os.path.dirname(formatted_path)).first()
            if parent_folder:
                folder_id = parent_folder.folder_id
        
        if folder_id:
            # Find all shares for this folder
            shares = session.query(Share).filter_by(folder_id=folder_id).all()
            source_mac = self.metadata.get('mac_addr', '')
            
            for share in shares:
                # Skip the source device
                if share.mac_addr == source_mac:
                    continue
                
                # Get user information for the target device
                device = session.query(Device).filter_by(mac_addr=share.mac_addr).first()
                if not device:
                    logging.warning(f"[!] Device with MAC {share.mac_addr} not found")
                    continue
                
                # Create a relative path from the source folder to the target path
                rel_path = os.path.relpath(formatted_path, os.path.dirname(formatted_path))
                target_path = os.path.join(share.path, rel_path)
                
                # Create sync event
                sync_event = {
                    "event_id": generate_event_id(),
                    "event_type": "created",
                    "is_dir": True,
                    "src_path": target_path,
                    "origin": "Server",
                    "user_id": device.user_id,
                    "mac_addr": share.mac_addr,
                    "folder_id": folder_id
                }
                
                # Add to sync queue
                sync_queue.put(sync_event)
                logging.info(f"[+] Added directory sync event to queue for device {share.mac_addr}")
        
        self._persist_queue()
        logging.info(f"[+] Persisted sync queue to file.")
        self.echo() # 🔊

class CreateFile(SyncEvent):
    
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
    
    def apply(self):
        offset = 0
        file_data = b''
        blocklist = dict()
        packet_count = self.metadata['packet_count']
        logging.info(f"[+] Expecting {packet_count} packets...")

        for index in range(1, packet_count + 1): # Start from 1 to skip metadata packet
            data, hash = self.receive_valid_packet(self.connection, index)
            file_data += data
            blocklist[hash] = {"offset": offset, "size": len(data)} # data is binary data, hash is checksum
            offset += len(data)
        
        formatted_path = self.format_path(self.metadata['src_path'])
        os.makedirs(os.path.dirname(formatted_path), exist_ok=True)
        logging.info(f"[+] Writing file to: {formatted_path}")
        with open(formatted_path, 'wb') as f:
            f.write(file_data)
        logging.info(f"[+] File '{formatted_path}' received successfully.")

        self.handle_global_blocklist('add', blocklist, src_path=formatted_path) # 🌍 Adding to global_blocklist

        blocklist_serialised = {}
        for hash, data in blocklist.items():
            blocklist_serialised[hash] = base64.b64encode(json.dumps(data).encode()).decode()

        folder_id = self.metadata['folder_id']
        hash = self.metadata['hash']
        size = self.metadata['size']

        # Verify that the received file's hash matches the metadata hash
        calculated_hash = hashlib.md5(file_data).hexdigest()
        if calculated_hash != hash:
            logging.error(f"[!] Hash mismatch for file {formatted_path}. Expected: {hash}, Got: {calculated_hash}")
            # Consider whether to reject the file or mark it as corrupted
        else:
            logging.info(f"[+] File hash verified for {formatted_path}")

        # Create a new file entry in the database
        file_entry = File(
            folder_id=folder_id,
            path=formatted_path,
            size=size,
            hash=hash,
            version="v1.0",
            block_list=json.dumps(blocklist_serialised) # creates initial block_list
        )
        
        session.add(file_entry)
        session.commit()
        logging.info(f"[+] Added file entry to database: {formatted_path}")

        self.echo() # 🔊

class Delete(SyncEvent):
    def purge_directory(self):
        formatted_path = self.format_path(self.metadata['src_path'])
        logging.info(f"[+] Deleting directory and its contents: {formatted_path}")
        
        # Use post-order traversal to delete directory contents
        for root, dirs, files in os.walk(formatted_path, topdown=False):
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
        
        # Remove folder from database
        folder_entry = session.query(Folder).filter_by(path=formatted_path).first()
        if folder_entry:
            # Remove related share entries
            share_entries = session.query(Share).filter_by(folder_id=folder_entry.folder_id).all()
            for share in share_entries:
                session.delete(share)
            
            session.delete(folder_entry)
            session.commit()
            logging.info(f"[-] Folder and shares removed from database")

    def apply(self):
        # TODO check if file or folder
        if self.metadata['is_dir']:
            self.purge_directory()
            logging.info(f"[-] Directory '{self.metadata['src_path']}' deleted successfully.")
        else: 
            formatted_path = self.format_path(self.metadata['src_path'])
            try:
                os.remove(formatted_path)
                logging.info(f"[-] File '{formatted_path}' deleted successfully.")
            except FileNotFoundError:
                logging.info(f"[-] File '{formatted_path}' already deleted or not found.")
            except Exception as e:
                logging.error(f"[-] Error deleting file '{formatted_path}': {e}")

            file_entry = session.query(File).filter_by(path=formatted_path).first()

            if file_entry:
                session.delete(file_entry)
                session.commit()
                logging.info(f"[-] File entry for '{formatted_path}' deleted from database.")
            else:
                logging.error(f"[-] No file entry found for '{formatted_path}' in database.")
        
        self.echo() # 🔊

class Move(SyncEvent):
    # def format_dest_path(self) -> str:

    #     remove_prefix = session.query(Share).filter_by(folder_id=self.metadata['folder_id'], username=self.metadata['user']).first().path
    #     new_prefix = session.query(Folder).filter_by(folder_id=self.metadata['folder_id']).first().path

    #     # Remove the old prefix and add the new one
    #     if self.metadata['dest_path'].startswith(remove_prefix):
    #         relative_path = self.metadata['dest_path'][len(remove_prefix):]  # Get the path after the prefix
    #         updated_path = new_prefix + relative_path
    #         logging.info(f"[F] Formatted Path: {updated_path}")
    #     else:
    #         logging.info("Prefix not found in path")
    #     return updated_path
    
    def apply(self):
        
        # Format source and destination paths
        src_path = self.format_path(self.metadata['src_path'])  
        dest_path = self.format_path(self.metadata['dest_path'])
        
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
        
        self.echo() # 🔊

class Modify(SyncEvent):
    def apply(self):
        formatted_path = self.format_path(self.metadata['src_path']) #🆗
        logging.info(f"[+] Processing modification for file: {formatted_path}") #🆗
        
        # Get block info packet first
        blocklist_packet = self.receive_valid_packet(self.connection, "blocklist") #🆗
        updated_blocklist = blocklist_packet.get('blocklist', {}) #🆗
        logging.info(f"[+] Received block info with {len(updated_blocklist)} blocks") #🆗

        # Get existing file's block list from database
        file_entry = session.query(File).filter_by(path=formatted_path).first() #🆗
        if not file_entry:  #🆗
            logging.error(f"[!] No database entry found for file: {formatted_path}") #🆗
            return #🆗

        # Parse the existing block list
        current_blocklist = {} #🆗
        if file_entry.block_list: #🆗
            serialized_blocks = json.loads(file_entry.block_list) #🆗
            for hash_key, serialized_data in serialized_blocks.items(): #🆗
                current_blocklist[hash_key] = json.loads(base64.b64decode(serialized_data.encode()).decode()) #🆗
        
        logging.info(f"[+] Current block list has {len(current_blocklist)} blocks") #🆗
        
        # Create temporary file path
        temp_file_path = f"{formatted_path}.tmp_{int(time.time())}" #🆗
        logging.info(f"[+] Creating temporary file: {temp_file_path}") #🆗
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(formatted_path), exist_ok=True) #🆗
        
        # Track used blocks for later cleanup
        used_blocks = set() #🆗
        # Track new blocks to add to global blocklist
        new_globalblocks = {} #🆗
        # Build new blocklist to replace the old one
        rebuilt_blocklist = {} #🆗
        
        # Open temp file for writing
        with open(temp_file_path, 'wb') as temp_file: #🆗
            offset = 0 #🆗
            # Process each block in the updated blocklist
            for block_hash, block_info in updated_blocklist.items(): #🆗
                block_offset = block_info.get('offset', 0) #🆗
                block_size = block_info.get('size', 0) #🆗
                block_data = None #🆗
                
                # Try to find the block in the current file
                if block_hash in current_blocklist: #🆗
                    logging.info(f"[+] Block {block_hash[:8]}... found in current file") #🆗
                    used_blocks.add(block_hash) #🆗
                    
                    try: #🆗
                        # Read the block from the current file
                        current_offset = current_blocklist[block_hash].get('offset', 0) #🆗
                        current_size = current_blocklist[block_hash].get('size', 0) #🆗
                        
                        with open(formatted_path, 'rb') as current_file: #🆗
                            current_file.seek(current_offset) #🆗
                            block_data = current_file.read(current_size) #🆗
                    except Exception as e: #🆗
                        logging.error(f"[!] Error reading block from current file: {e}") #🆗
                        block_data = None #🆗
                
                # If not found or error reading from current file, try global blocklist
                elif block_data is None and hasattr(self, 'handle_global_blocklist'): #🆗
                    logging.info(f"[+] Trying to find block {block_hash[:8]}... in global blocklist") #🆗
                    block_data = self.handle_global_blocklist('query', query=block_hash) #🆗
                
                # If still not found, request from client
                if not block_data: # No block data found in current file or global blocklist #🆗
                    logging.info(f"[+] Requesting block {block_hash[:8]}... from client") #🆗
                    
                    # Request specific block from client
                    request = { #🆗
                        "event_type": "request", #🆗,
                        "is_dir": False, #🆗
                        "origin": "NoHash", #🆗
                        "src_path": self.metadata['src_path'], #🆗
                        "block_offset": block_offset, #🆗
                        "block_size": block_size, #🆗
                        "block_hash": block_hash, #🆗
                    } #🆗
                    
                    # Maximum retries and initial delay
                    max_retries = 3
                    delay = 1  # seconds
                    
                    # Try to get the block data with simple retry
                    for attempt in range(max_retries):
                        try:
                            # Request the block
                            sync_job = Outgoing(request)
                            logging.info(f"[+] Requesting block {block_hash[:8]}... (attempt {attempt+1}/{max_retries})")
                            result = sync_job.start_server(self.address)
                            
                            # Check if we got a valid result
                            if isinstance(result, tuple) and len(result) == 2:
                                block_data, actual_hash = result
                                
                                # Verify the hash if data was received
                                if block_data and actual_hash == block_hash:
                                    logging.info(f"[+] Block {block_hash[:8]}... successfully received")
                                    break
                                else:
                                    logging.warning(f"[!] Block verification failed - Hash mismatch, retrying...")
                                    block_data = None  # Reset for retry
                                    time.sleep(delay)
                            else:
                                logging.warning(f"[!] Invalid result format from start_server, retrying...")
                                block_data = None
                                time.sleep(delay)
                        except Exception as e:
                            logging.error(f"[!] Error requesting block: {e}")
                            block_data = None
                            time.sleep(delay)
                    
                    if not block_data:
                        logging.error(f"[!] Failed to retrieve block {block_hash[:8]}... after {max_retries} attempts")
                    
                    # Add this new block to our global_blocklist tracking
                    new_globalblocks[block_hash] = {#🆗
                        "offset": offset,#🆗
                        "size": len(block_data),#🆗
                        "src_path": formatted_path#🆗
                    }
                
                # If we have valid block data, write it to our temp file
                if block_data:#🆗
                    temp_file.write(block_data)#🆗
                    
                    # Update rebuilt_blocklist with this block's info
                    rebuilt_blocklist[block_hash] = {#🆗
                        "offset": offset,#🆗
                        "size": len(block_data)#🆗
                    }#🆗
                    
                    # Update offset for next block
                    offset += len(block_data)#🆗
                else:#🆗
                    logging.error(f"[!] Failed to retrieve block {block_hash[:8]}...") #🆗
        
        # Cleanup: Remove unused blocks from global_blocklist
        unused_blocks = set(current_blocklist.keys()) - used_blocks #🆗
        if unused_blocks and hasattr(self, 'handle_global_blocklist'): #🆗
            logging.info(f"[+] Removing {len(unused_blocks)} unused blocks from global blocklist") #🆗
            self.handle_global_blocklist('delete', hashlist=list(unused_blocks), src_path=formatted_path) #🆗
        
        # Add new blocks to global blocklist
        if new_globalblocks and hasattr(self, 'handle_global_blocklist'): #🆗
            logging.info(f"[+] Adding {len(new_globalblocks)} new blocks to global blocklist")#🆗
            self.handle_global_blocklist('add', blocklist=new_globalblocks, src_path=formatted_path) #🆗
        
        # Rename temp file to original file 
        logging.info(f"[+] Replacing original file with reconstructed file") #🆗
        os.replace(temp_file_path, formatted_path) #🆗
        
        # Update database entry
        file_entry.hash = self.metadata['hash'] #🆗
        file_entry.size = os.path.getsize(formatted_path) #🆗
        file_entry.version = self.metadata.get('version', 'v1.0') # if version not provided, default to 'v1.0' #🆗
        
        # Serialize the rebuilt blocklist for database storage
        serialized_rebuilt = {} #🆗
        for hash_key, block_data in rebuilt_blocklist.items(): #🆗
            serialized_rebuilt[hash_key] = base64.b64encode(json.dumps(block_data).encode()).decode() #🆗
        
        file_entry.block_list = json.dumps(serialized_rebuilt) #🆗 
        session.commit() #🆗
        logging.info(f"[+] Updated database entry for: {formatted_path}") #🆗
        logging.info(f"[+] File modification complete") #🆗
        
        self.echo() # 🔊
        
class Block(SyncEvent):

    def apply(self):
        packet_count = self.metadata['packet_count']
        logging.info(f"[+] Expecting {packet_count} packets to build requested block...")
        block_data = b''
        actual_hash = None
        
        try:
            for index in range(1, packet_count + 1): # Start from 1 to skip metadata packet
                try:
                    result = self.receive_valid_packet(self.connection, index)
                    if isinstance(result, tuple) and len(result) == 2:
                        decoded_data, hash_value = result
                        block_data += decoded_data
                        actual_hash = hash_value  # Use the hash from the last packet
                    else:
                        logging.error(f"[!] Invalid result from receive_valid_packet: {result}")
                        return None, None
                except Exception as e:
                    logging.error(f"[!] Error receiving packet {index}: {e}")
                    return None, None
            
            return block_data, actual_hash
        except Exception as e:
            logging.error(f"[!] Error in Block.apply(): {e}")
            return None, None
        
##############################################################################################
##############################################################################################
##############################################################################################
##############################################################################################
##############################################################################################

class Outgoing(Sync):
    def __init__(self, event):
        super().__init__()
        self.PORT = 6969
        self.src_path = event['src_path']
        self.is_dir = event['is_dir']
        self.origin = event['origin']
        self.event_type = event['event_type']
        self.folder_id = event.get('folder_id')
        logging.info(f"Created base attributes of Outgoing object")
        # Additional properties based on event type
        if not self.is_dir and self.event_type in ['created', 'modified']:
            logging.info(f"Creating packet for file creation")
            self.local_path = event['local_path'] or None
            self.packets = self.create_packet(self.local_path)
            self.packet_count = len(self.packets)
            self.hash = event.get('hash') or file_to_hash.get(self.src_path)
            logging.info(f"added attributes: self.packets(too long to display) packet_count: {self.packet_count}, hash: {self.hash}, local_path: {self.local_path}")

        # elif not self.is_dir and self.event_type == 'modified':
        #     self.blocks = self.create_blocklist()
        #     self.block_count = len(self.blocks)
        #     self.hash = event.get('hash') or file_to_hash.get(self.src_path)
        #     self.packets = self.create_packet(self.local_path)
        #     self.packet_count = len(self.packets)
        #     logging.info(f"added attributes: {self.blocks}, {self.block_count}, {self.hash}, {self.packets}, {self.packet_count}")
            
        #     # Get file version from database
        #     file = session.query(File).filter_by(path=self.src_path).first()
        #     self.version = file.version if file else 'v1.0'

        if self.event_type == 'moved':
            self.dest_path = event['dest_path']

        if self.event_type == 'request':
            self.block_offset = event['block_offset']
            self.block_size = event['block_size']
            self.block_hash = event['block_hash']
    
    def _build_metadata(self) -> dict:
        metadata = {
            "index":      0,
            "event_type": self.event_type,
            "src_path":     self.src_path,
            "is_dir":     self.is_dir,
            "origin":     self.origin,
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

        if self.event_type == 'request':
            metadata['block_offset'] = self.block_offset
            metadata['block_size'] = self.block_size
            metadata['block_hash'] = self.block_hash
        
        return metadata
    
        '''
        block_list looks like {'hash1'={},'hash2'={},'hash3'={}}
        '''
    def get_blocksize(self) -> int:
        """Determine block size based on file size."""
        logging.info(f"[+] Getting block size for: {self.local_path}")
        try:
            file_size = os.path.getsize(self.local_path)
            
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
            logging.error(f"File not found: {self.local_path}")
            return 128 * 1024  # Default to smallest block size if file not found
        except Exception as e:
            logging.error(f"Error getting file size: {e}")
            return 128 * 1024  # Default to smallest block size on error

    def create_packet(self, formatted_path) -> list: # If formatted_path is None, use self.src_path
        # Use dynamic block size based on file size
        block_size = self.get_blocksize()
        
        with open(formatted_path or self.src_path, 'rb') as f:
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
        logging.info(f"[+] Sending packet {packet.get('index', 'metadata')} to {self.src_path}")
        """Send a packet with retry logic."""
        payload = json.dumps(packet).encode('utf-8')
        header = struct.pack('!I', len(payload))
        message = header + payload
        
        max_retries = 3
        retry_count = 0
        sent = False
        
        while not sent and retry_count < max_retries:
            try:
                outgoingsock.sendall(message)
                
                # Wait for acknowledgement with timeout
                outgoingsock.settimeout(5.0)
                response = outgoingsock.recv(3)
                
                if response == self.RESPONSE_OK:
                    sent = True
                else:
                    logging.warning(f"[-] Packet {packet.get('index', 'metadata')} failed checksum, retrying")
                    retry_count += 1
                    time.sleep(0.5)  # Brief delay before retry
                    
            except socket.timeout:
                logging.warning(f"[-] Timeout waiting for acknowledgement, retrying")
                retry_count += 1
                time.sleep(0.5)
                
            except Exception as e:
                logging.error(f"[-] Error sending packet: {e}")
                retry_count += 1
                time.sleep(0.5)
        
        if not sent:
            raise ConnectionError(f"Failed to send packet after {max_retries} attempts")
        
    def OG_send_packet(self, outgoingsock: socket.socket, packet: dict) -> None:
        payload = json.dumps(packet).encode('utf-8')
        header = struct.pack('!I', len(payload))
        message = header + payload  # Join header and payload
        sent = False
        retries = 0

        while not sent and retries < 10:
            outgoingsock.sendall(message)
            response = outgoingsock.recv(3)
            if response == self.RESPONSE_OK:
                # logging.info(f"[+] Packet {packet['index']} transmitted successfully.") # 🔔
                sent = True
            else:
                retries += 1
                logging.info(f"[-] Packet {packet['index']} failed checksum, retrying ({retries}/10)...")

        if not sent:
            logging.error(f"❌ Packet {packet['index']} failed after 10 retries, giving up.")

    def initialise_copy(self, user_path, root_folder_path, folder_id, folder_label, username, mac_addr):

        stack = [self.src_path]
        directories = []
        files = []

        while stack:
            current = stack.pop()
            logging.info(f'📂 Traversing: {current}')
            directories.append(current)

            src_path = user_path + '/' + os.path.relpath(current, root_folder_path)
            logging.info(f'📂 Found directory: {current} i.e. for User: {src_path}')

            metadata = {
            "index":      0,
            "event_type": 'created',
            "src_path": src_path,
            "is_dir": True,
            "origin": 'initialise_copy',
            "folder_id": folder_id,
            }

            outgoingsock = socket.socket() 
            outgoingsock.connect((ip_map["users"][username][str(mac_addr)], 6969))

            logging.info(f"[+] Sending metadata packet: {metadata}")
            self.OG_send_packet(outgoingsock, metadata)

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
                    
                    files.append(full_path)
                    # TODO send the files to be made

                    src_path = user_path + '/' + os.path.relpath(full_path, root_folder_path)

                    logging.info(f'📖 Found file: {full_path} i.e. for User: {src_path}')
                    event = {
                        "event_type": "created",
                        "src_path": src_path,
                        "is_dir": False,
                        "origin": "mkdir",
                        "folder_id":folder_id,
                        "local_path":full_path,
                        "index" : '0',
                        "hash": file_to_hash.get(full_path),
                        "size": os.path.getsize(full_path),
                    }
                    
                    outgoingsock = socket.socket() 
                    outgoingsock.connect((ip_map["users"][username][str(mac_addr)], 6969))

                    send_file = Outgoing(event)
                    
                    logging.info('[+] initialised send_file object using class Outgoing')
                    event['packet_count'] = len(send_file.packets)
                    
                    logging.info(f"[+] Sending metadata packet: {event}")
                    send_file.OG_send_packet(outgoingsock, event)
                    logging.info(f"[+] Sent metadata for {send_file.event_type} event: {send_file.src_path}")

                    if hasattr(send_file, 'packets') and send_file.packets:
                        logging.info(f"[+] Sending {send_file.packet_count} data packets")
                        for packet in send_file.packets:
                            self.OG_send_packet(outgoingsock, packet)

                        logging.info(f"[+] Successfully sent {self.event_type} event data")
                    del send_file
                    
        
        # folder = session.query(Share).filter_by(folder_id=folder_id).first()
        # if folder.type == 'sync_bothways':
        #     establish_packet = {
        #         "event_type": "establish",
        #         "folder_id": folder_id,
        #         "folder_label": folder_label,
        #         "src_path": user_path + '/' + os.path.relpath(self.src_path, root_folder_path),
        #         "size": folder.size,
        #         "type": "sync_bothways"
        #     }
        #     self.OG_send_packet(outgoingsock, establish_packet)

        logging.info('✅ Traversal Complete')
        logging.info(f'🗃️ Directories: {directories}')
        logging.info(f'📑 Files: {files}')

    def start_server(self, address) -> bool:
        """Send event data to a client."""
        outgoingsock = socket.socket()
        ip = address[0]
        # port = address[1] if isinstance(address, tuple) and len(address) > 1 else self.PORT
        port = self.PORT

        try:
            # Set a reasonable timeout
            outgoingsock.settimeout(10.0)
            
            logging.info(f"Connecting to client at {ip}:{port}")
            outgoingsock.connect((ip, port))
            logging.info(f"[+] Connected to client at {ip}:{port}")
            
            # Build and send metadata
            metadata = self._build_metadata()
            logging.info(f"[+] Sending metadata for {self.event_type} event: {self.src_path}")
            self.send_packet(outgoingsock, metadata)
            
            if self.event_type == 'request':
                # Reveive the requested block
                # receive_valid_packet(self, connection: socket.socket, index: int) -> bytes:
                # Incoming just needs a connection
                # TODO create incoming object to receive the block

                incoming_block = Incoming(connection=outgoingsock)     # 🗣️ REUSING INCOMING CLASS
                logging.info(f"[+] Created incoming_block object: {incoming_block}")
                # TODO receive metadata.
                block_data, actual_hash = incoming_block.receive_metadata()
                logging.info(f"[+] Block data received: {block_data}, actual hash: {actual_hash}")
                return block_data, actual_hash

            # For modified files, send the blocklist
            if self.event_type == 'modified' and hasattr(self, 'blocks'):
                blocklist_packet = {
                    "index": "blocklist",
                    "blocklist": self.blocks
                }
                logging.info(f"[+] Sending block list for modified file")
                self.send_packet(outgoingsock, blocklist_packet)
            
            # For file content (created or modified files)
            if hasattr(self, 'packets') and self.packets:
                logging.info(f"[+] Sending {len(self.packets)} data packets")
                for packet in self.packets:
                    self.send_packet(outgoingsock, packet)
            
            logging.info(f"[+] Successfully sent {self.event_type} event data")
            return True
            
        except socket.timeout:
            logging.error(f"[!] Connection timed out to {ip}:{port}")
            return False
        except ConnectionRefusedError:
            logging.error(f"[!] Connection refused by {ip}:{port}")
            return False
        except Exception as e:
            logging.error(f"[!] Error sending to {ip}:{port}: {e}")
            return False
        finally:
            try:
                outgoingsock.close()
            except:
                pass
            
# class Build_Instructions(Outgoing):
#     pass
# class Requests(Outgoing):
#     pass


    '''
        request_packet = { #🆗
        "index": "request", #🆗,
        "src_path": self.metadata['src_path'], #🆗
        "offset": block_offset, #🆗
        "size": block_size, #🆗
        "block_hash": block_hash, #🆗
    } #🆗
    # '''
    # def __init__(self, request_packet):
    #     pass

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

def determine_event_recipients(event):
    """Determine which clients should receive this event."""
    recipients = []
    
    try:
        # Extract event information
        folder_id = event.get('folder_id')
        event_type = event.get('event_type')
        origin_mac = event.get('mac_addr', None)  # Original source device
        
        # For folder-related events, we need to find all devices that share this folder
        if folder_id:
            # Get all shares for this folder
            shares = session.query(Share).filter_by(folder_id=folder_id).all()
            
            for share in shares:
                # Skip the origin device to avoid echo
                if origin_mac and share.mac_addr == str(origin_mac):
                    continue
                
                # Find device's user and IP
                device = session.query(Device).filter_by(mac_addr=share.mac_addr).first()
                if not device:
                    logging.warning(f"Device with MAC {share.mac_addr} not found")
                    continue
                
                # Find device's IP
                user = session.query(User).filter_by(user_id=device.user_id).first()
                if not user:
                    logging.warning(f"User with ID {device.user_id} not found")
                    continue
                
                # Check if user is in IP map
                if user.name in ip_map['users'] and share.mac_addr in ip_map['users'][user.name]:
                    ip_addr = ip_map['users'][user.name][share.mac_addr]
                    recipients.append({
                        'user': user.name,
                        'mac_addr': share.mac_addr,
                        'ip': ip_addr,
                        'folder_id': folder_id
                    })
        
        # If no recipients found but we have a specific target
        if not recipients and 'target_recipient' in event:
            recipients.append(event['target_recipient'])
        
        return recipients
        
    except Exception as e:
        logging.error(f"Error determining recipients: {e}")
        return []


def sync_queue_worker(): 
    while True:
        sync_active.wait()  # Wait until resumed
        
        try:
            # Get the next event to process
            event = sync_queue.get()
            logging.info(f"Processing event: {event}")
            
            # Determine which clients should receive this event
            recipients = determine_event_recipients(event)
            
            if not recipients:
                logging.warning(f"No recipients found for event: {event['src_path']}")
                sync_queue.task_done()
                continue
            
            success_count = 0
            failed_recipients = []
            
            # Process each recipient
            for recipient in recipients:
                try:
                    logging.info(f"Sending event to {recipient['user']} on device {recipient['mac_addr']} at {recipient['ip']}")
                    
                    # Create a sync job for this specific recipient
                    sync_job = Outgoing(event)
                    status = sync_job.start_server((recipient['ip'], 6969))
                    
                    if status:
                        logging.info(f"✅ Successfully sent event to {recipient['user']} ({recipient['ip']})")
                        success_count += 1
                    else:
                        logging.error(f"❌ Failed to send event to {recipient['user']} ({recipient['ip']})")
                        failed_recipients.append(recipient)
                        
                except Exception as e:
                    logging.error(f"❌ Error sending to {recipient['user']} ({recipient['ip']}): {e}")
                    failed_recipients.append(recipient)
            
            # Handle the overall status
            if success_count > 0:
                logging.info(f"✅ Event sent to {success_count}/{len(recipients)} recipients")
            
            # If we had failures but some successes, create new events for the failed recipients
            if failed_recipients and success_count > 0:
                for recipient in failed_recipients:
                    new_event = event.copy()
                    new_event['target_recipient'] = recipient
                    sync_queue.put(new_event)
                    logging.info(f"🔁 Requeued event for {recipient['user']} ({recipient['ip']})")
            
            # If all recipients failed, requeue the original event and pause
            elif success_count == 0:
                sync_queue.put(event)
                logging.error(f"❌ Failed to send event to ANY recipients. Pausing queue.")
                sync_active.clear()  # Pause on complete failure
                
                # Schedule a retry after 30 seconds
                threading.Timer(30.0, lambda: sync_active.set()).start()
                logging.info("⏱️ Scheduled retry in 30 seconds")
            
        except Exception as e:
            logging.error(f"❌ Error in sync queue worker: {e}")
            sync_active.clear()  # Pause on failure
            
            # Schedule a retry after 10 seconds
            threading.Timer(10.0, lambda: sync_active.set()).start()
            logging.info("⏱️ Scheduled retry in 10 seconds")
            
        finally:
            sync_queue.task_done()
            # Save current queue state
            all_events = list(sync_queue.queue)
            with open("sync_queue.json", "w") as f:
                json.dump(all_events, f, indent=2)
##############################################################################################
##############################################################################################
##############################################################################################
##############################################################################################
##############################################################################################




# TODO: need to create a queue to send out outgoing data to other clients!


# TODO make system wide blocklist
class Global_Blocklist():
        # action='add' blocklist=[{'hash1':{'offset':offset, 'size':size}}, {'hash2':{'offset':offset, 'size':size}}] src_path='/home/...'
        # action='delete' delete that block as well as all instances of it. send: src_path='/home/...' + hashlist(list of hashes to be deleted!)
        # action='move' renames source path of file for specified hash. e.g. {'hash1':{'src_path':'/home/file.txt', ...}} -> {'hash1':{'src_path':'/home/FILE.txt', ...}} 
        # action='query' asks back file data in binary for hash specified in parameter 'query'!
    def __init__(self, action=None, blocklist=None, hashlist=None, src_path=None, dest_path=None, query=None):
        self.action = action # command
        self.blocklist = blocklist # blocklist/lists
        self.hashlist = hashlist # list of hashes to be deleted usually given at the end of modifying a file.
        self.src_path = src_path
        self.dest_path = dest_path
        self.query = query
        self.handle_request()

    def handle_request(self):
        if self.action == 'add':
            self.add_blocklist()
        elif self.action == 'delete':
            self.delete_blocklist()
        elif self.action == 'move':
            self.update_blocklist()
        elif self.action == 'query':
            self.query_blocklist()
        pass

    def write_blocklist(self): # TODO in the case of writing a blocklist to a file.
        with open(ip_file, "w") as file:
            json.dump(ip_map, file, indent=2)

    def add_blocklist(self): # TODO in the case of adding a hash to a file.
        for hash, position in self.blocklist.items():
            position['src_path'] = self.src_path
            global_blocklist[hash] = position
        self.write_blocklist()

    def delete_blocklist(self): # TODO in the case of removing a hash from a file.
        for hash in self.hashlist:
            if hash in global_blocklist and global_blocklist[hash].get('src_path') == self.src_path:
                global_blocklist.pop(hash)  # Only remove if hash exists and path matches
        self.write_blocklist()  # save changes to file

    def update_blocklist(self): # TODO in case file is moved
        for hash, data in global_blocklist.items():
            if data.get('src_path') == self.src_path:
                data['src_path'] = self.dest_path
        self.write_blocklist()  # Save changes to file

    def query_blocklist(self):
        hash_to_query = self.query
        if hash_to_query in global_blocklist:
            block_info = global_blocklist[hash_to_query]
            src_path = block_info.get('src_path')
            offset = block_info.get('offset')
            size = block_info.get('size')
            
            if src_path and offset is not None and size is not None:
                try:
                    with open(src_path, 'rb') as file:
                        file.seek(offset)
                        data = file.read(size)
                        logging.info(f"Successfully read block data for hash: {hash_to_query}")
                        return data
                except Exception as e:
                    logging.error(f"Error reading block data: {e}")
                    return None
            else:
                logging.error(f"Incomplete block information for hash: {hash_to_query}")
                return None 
            logging.error(f"Hash not found in global blocklist: {hash_to_query}")
            return None

class build_instruction():
    def __init__(self):
        pass

    # NOTE: rest of the instruction's such as create/delete/moved can be stored and sent as it was received from client -> server
    # NOTE: event_type = 'created'. just store in sync_queue the instructions for created.
# QUEUE SYSTEM




if __name__ == "__main__":
    # Start the main server socket
    main_thread = threading.Thread(target=main, daemon=True)
    main_thread.start()
    logging.info("[START] Started main server thread")
    
    # Start the sync worker thread
    sync_active.set()  # Make sure it's active from the start
    sync_worker_thread = threading.Thread(target=sync_worker)
    sync_worker_thread.start()
    logging.info("[START] Started sync queue worker thread")
    
    # Load the global blocklist
    global_blocklist_file = "blocklist.json"
    if os.path.exists(global_blocklist_file):
        with open(global_blocklist_file, "r") as file:
            global_blocklist = json.load(file)
    else:
        global_blocklist = {}
    logging.info(f'[LOAD] Loaded global blocklist with {len(global_blocklist)} entries')

    # Load IP mapping
    ip_file = "ip_map.json"
    if os.path.exists(ip_file):
        with open(ip_file, "r") as file:
            ip_map = json.load(file)
    else:
        ip_map = {"users": {}}
    logging.info(f'[LOAD] Loaded IP map with {len(ip_map["users"])} users')

    sync_list_file = "sync_list.json"
    if os.path.exists(sync_list_file):
        with open(sync_list_file, "r") as file:
            sync_list = json.load(file)
    else:
        sync_list = {}
    logging.info(f'Loaded sync list with {len(sync_list)} events')

    # Load pending invites
    invites_file = "invites.json"
    if os.path.exists(invites_file):
        with open(invites_file, "r") as file:
            invites = json.load(file)
    else:
        invites = {"folders": {}, "groups": {}}
    logging.info(f'[LOAD] Loaded invites data')
    
    # Build file hash mappings
    file_to_hash = {f.path: f.hash for f in session.query(File).all()}
    logging.info(f'[LOAD] Loaded file_to_hash with {len(file_to_hash)} entries')
    
    # Keep main thread alive
    # try:
    #     while True:
    #         time.sleep(60)  # Check every minute
    #         # Log current queue status
    #         queue_size = sync_queue.qsize()
    #         if queue_size > 0:
    #             logging.info(f"Current sync queue size: {queue_size}")
    # except KeyboardInterrupt:
    #     logging.info("Server shutting down")

    # NOTE: all these are dictionaries therefore automatically global variables


'''

Efficiently reconstructs the file block by block:

Reads from existing file when possible
Queries global blocklist for shared blocks
Requests missing blocks from client only when necessary
Performs intelligent block management:

Tracks which blocks were used and which are new
Removes unused blocks from global blocklist
Adds new blocks to global blocklist
Rebuilds the file's blocklist with accurate offsets and sizes
Uses a robust temp file approach:

Creates a temporary file with timestamp
Builds the new file piece by piece
Only replaces original file if reconstruction was successful
Handles error conditions gracefully:

Verifies received blocks match expected hashes
Logs each step for debugging
Maintains database consistency
Optimizes network usage:

Only requests blocks that aren't available locally
Reuses blocks across files when possible
This implementation achieves significant bandwidth savings for modified files by eliminating the need to retransmit blocks that haven't changed or are available elsewhere in the system.

'''

