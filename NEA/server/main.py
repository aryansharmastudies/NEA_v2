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

class Data_Response(Response): # TODO get this working.
    def __init__(self, requested_data):
        super().__init__()
        self.requested_data = requested_data # e.g. {'user':['name'], 'device':['user_id', 'name']}
        self.data = dict() # using a dictionary to store scraped data
        logging.info(f'Data_Response Object is made')
    
    def scrape(self): # used to scrape the database for requested data
        for table_name in self.requested_data: # itteratively goes through the each requested table!
            scraped_data = scrape_db(table_name, self.requested_data[table_name]) # self.requested_data[table] => attributes requested for of that table.
            self.data[table_name] = scraped_data # scraped_data should be a list returned back!
        logging.info(f'scraped data to be returned!: {self.data}')

class Instruction_Response(Response):
    def __init__(self):
        super().__init__()
        logging.info(f'Instruction_Response Object is made')

class Blockdata_Response(Response):
    def __init__(self):
        super().__init__()
        logging.info(f'Blockdata_Response Object is made')
########## CRUD(create, read, update, delete) ####
def scrape_db(table_name, attributes): # scrapes db and returns back data
    # input: (device', ['user_id', 'name'])
    # expected output: [['kyoto', 'x230'],['kyoto', 'iphone5s'],['tokyo', 'chromebook']]
        # Map the table name to the corresponding SQLAlchemy model
    table_map = {
        'users': User,
        'devices': Device,
        'folders': Folder,
        # Add other tables here as needed 
    }
    # Get the SQLAlchemy model for the table
    table_model = table_map.get(table_name)
    if not table_model:
        logging.warning(f"Table '{table_name}' not found in table_map.")

    # Query the database for the specified attributes
    query = session.query(*[getattr(table_model, attr) for attr in attributes])
    results = query.all()

    # Convert the results into a list of lists
    scraped_data = [list(row) for row in results]
    return scraped_data

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

def create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type, user):
    # DONE check if folder_id exists!
    # DONE convert windows path to linux! USE REGEX!
    # TODO share it to all users... :<
    for folder in session.query(Folder):
        if folder.folder_id == str(folder_id):
            logging.info(f'Folder_id: {folder_id} already exists!')
            return json.dumps({'status': '409', 'status_msg': 'Folder with this folder_id already exists'})
    
    result = validate_directory(directory)
    if result == '400':
        return json.dumps({'status': '400', 'status_msg': 'Invalid directory format'})


    # DONE find username given mac_addr of host
    # mac_addr -> user_id -> username
    host_name = user
    host_id = session.query(User).filter_by(name=host_name).first().user_id
    # host_id = session.query(Device).filter_by(mac_addr=mac_addr).first().user_id
    # hostname = session.query(User).filter_by(user_id=host_id).first().name
    logging.info(f'👤Host: {user} with User_ID: {host_id} is creating folder📂: {folder_label} with folder_id: {folder_id} in directory: {directory}')

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
            logging.info(f'User: {username} not found')
            return json.dumps({'status': '404', 'status_msg': 'User not found'})
        
        logging.info(f'User: {username} found with User_ID: {target_user_id}')
        device = session.query(Device).filter_by(user_id=target_user_id, name=device_name).first() # 🌸
        
        if not device:
            logging.info(f'Device: {device_name} not found for User: {username}')
            return json.dumps({'status': '404', 'status_msg': 'Device not found'})
        
        device_mac_addr = device.mac_addr # gets devices mac addr # 🌸
        logging.info(f'Device: {device_name} found with Mac_addr: {device_mac_addr}')

        if username not in ip_map["users"]:
            logging.info(f'User: {username} not found in ip_map')
            return json.dumps({'status': '404', 'status_msg': 'User not found in ip_map'})

        logging.info(f'{ip_map["users"][username]}')        
        if str(device_mac_addr) not in ip_map["users"][username]:
            logging.info(f'Device: {device_name} not found in ip_map')
            return json.dumps({'status': '404', 'status_msg': 'Device not found in ip_map'})
        
        logging.info(f'ip of device: {ip_map["users"][username][device_mac_addr]}')
        ip = ip_map["users"][username][device_mac_addr] # gets users ip address
        
        logging.info(f'Sending authorisation request to {username}, device: {device.name}, mac_addr: {device_mac_addr},  ip: {ip}')
        status = send(json.dumps({'action': 'authorise', 'user': username}), ip, 6000) # sends a ping through!
        logging.info(f'User Status: {status} (400/404 -> failed, 200 -> success)')
        # either no response -> add to list of invites!!
        # or another user is online(from same ip - maybe ip changed/user logged into device)
        # or correct user is online
        if status == '400' or status == '404': # if request fails
            logging.info(f'Authorisation failed for {username} with ip: {ip}')
            # adds to invites.json
            logging.info(f'invites.json BEFORE adding: {invites}')
            if username not in invites["folders"]: # first check if the user is in the invites file 🌸
                invites["folders"][username] = {} # 🌸
                invites["folders"][username][device_mac_addr] = [] # if not, add them 🌸
            elif device_mac_addr not in invites["folders"][username]: # then check if the device is in the invites file 🌸
                invites["folders"][username][device_mac_addr] = [] # if not, add it 🌸

            invites["folders"][username][device_mac_addr].append([folder_label, folder_id, host_name])# ✅ ADD THE HOST WHO IS SENDING INVITE! 🌸
            logging.info(f'invites.json AFTER adding: {invites}')
            with open(invites_file, "w") as file:
                json.dump(invites, file, indent=2)
         # everytime user logs in, check if they are in the invites file!!

            # ❗no need to return if user is offline, as the user will get the invite when they log in.
            # return json.dumps({'status': '400', 'status_msg': 'Ping failed'})
        
        
        ############# TODO - if the user is online, send folder invite to them... ##################
        
        
        
        elif status == '200': # if authorisation is successful.  
            logging.info(f'Authorisation successful for {username} with ip: {ip}')
            data = send(json.dumps({'action': 'add_folder', 'folder_label': folder_label, 'folder_id': folder_id}), ip, 6000) # TODO needs to be displayed on clients side through websockets.
            if data != False: # NOTE MAYBE SHOULD SCRAP THIS SINCE IT WILL WAIT UNNECESSARILY
                data = json.loads(data)
                guest_dir = data['directory']
                shared_user = Share(folder_id=folder_id, mac_addr=mac_addr, path=guest_dir)
                session.add(shared_user) # im sure with a for loop you can itterate and add many 'share' objects to the session, then commit them.
                session.commit()
            else:
                logging.info(f'data {username} sent has failed: {data}')


    # use async to ask the currently active users
    # or else, put instruction in a json file!!!
    # and whenever user logs in, check if they are in the file.

    # directory = ~/Desktop/LINUX
    # e.g. ~/Desktop/LINUX -> ~/02/290128321/Desktop/LINUX i.e. ~/<user_id>/<mac_addr>/<folder_name>
    
    directory = directory.split('/')
    directory.insert(1, str(host_id)) # insert user_id
    directory.insert(2, str(mac_addr)) # insert mac_addr
    directory = '/'.join(directory)
    directory = os.path.expanduser(directory) 
    logging.info(f'Creating folder directory: {directory}')
    try: 
        os.makedirs(directory)
    except FileExistsError:
        logging.info(f'⚠️ Directory {directory} already exists, skipping creation.')

    # NOTE: ADD TO DB ONLY AFTER DIRECTORY PATH IS FORMATTED CORRECTLY! AND DIRECTORY IS CREATED!
    folder = Folder(mac_addr=mac_addr, name=folder_label, folder_id=folder_id, path=directory, type=folder_type)
    session.add(folder)
    session.commit()

    logging.info(f'Directory created: {directory}')

    return json.dumps({'status': '201', 'status_msg': 'Folder added successfully'})

def validate_directory(directory): # NOTE need this for checking if directory is either valid unix or windows. if windows -> convert to unix.
        # Check if the directory is in Unix format
    unix_format_check = re.search(r'^~(/.+)*', directory)
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


########## SOCKETS ###############################
def send(message, ip, port): 
    logging.info(f'Sending: {message} to {ip} on port {port}')
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        c.connect((ip, port))
    except: 
        return '400' 
    c.send(message.encode('utf-8'))
    client_data = c.recv(1024).decode('utf-8')
    logging.info(f'client_data: {client_data}')
    client_data = json.loads(client_data)
    
    status_code = client_data.get('status_code', '400')
    status_msg = client_data.get('status_msg', False)
    data = client_data.get('data', False)

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
        user = client_data['user']
        status = create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type, user)
        logging.info(f'Sending folder status: {status}')
        clientsocket.send(str(status).encode('utf-8'))

    elif action == 'remove_user': # TODO should be a potential option for admin.
        username = client_data['username']
        logging.info(f'Removing user: {username}')
        # Remove user logic here

    elif action == 'request':
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
    incomingsock.bind((ip, 7000))
    logging.info(f"[+] Listening on {ip}:7000...")
    incomingsock.listen(1) # only can recieve data from one client at a time otherwise, it can get messy.

    while True:
        connection, address = incomingsock.accept() # if client does s.connect((server_name, 8000))
        logging.info(f'Connection from {address} has been established!')
        sync_job = Incoming(connection, address)
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
        self.PORT = 7000
        self.HEADER_SIZE = 4
        self.RESPONSE_OK = b'ACK'
        self.RESPONSE_ERR = b'ERR'

class Incoming(Sync):
    def __init__(self, connection, address):
        super().__init__()
        self.connection = connection
        self.address = address
        
    def recv_exact(self, connection: socket.socket, num_bytes: int) -> bytes:
        """Receive an exact number of bytes from the socket."""
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
            CreateDir(metadata, self.address).apply() # ↙️
        elif not metadata['is_dir'] and event_type == 'created': # i.e. a file is created
            CreateFile(metadata, self.address, self.connection).apply() # ↙️
        elif event_type == 'deleted':
            Delete(metadata, self.address).apply() # ↙️
        elif event_type == 'moved':
            Move(metadata, self.address).apply() # ↙️
        elif event_type == 'modify':
            Modify(metadata, self.address, self.connection).apply() # ↙️
            pass

class SyncEvent(Incoming):
    def __init__(self, metadata, address, connection=None): # ⬅️ added connection parameter!
        self.metadata = metadata
        super().__init__(connection, address) 

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

    def _get_mac_addr(self, user) -> str:
        for mac_addr in ip_map["users"][user]:
            if mac_addr == str(mac_addr):
                return mac_addr
            
    def format_path(self) -> str:
        user = self.metadata['user']
        user_id = session.query(User).filter_by(name=user).first().user_id
        mac_addr = self._get_mac_addr(user)
        raw_path = self.metadata['src_path']
        logging.info(f"[+] Formatting path: {raw_path}")
        src_path = os.path.normpath(raw_path).replace('\\', '/')
        src_path = src_path.split('/')
        src_path = src_path[3:]
        src_path.insert(0, str(mac_addr))
        src_path.insert(0, str(user_id))
        src_path.insert(0, '~')
        src_path = '/'.join(src_path)       
        formatted_path = os.path.expanduser(src_path)
        logging.info(f"[+] Formatted path: {formatted_path}")
        return formatted_path
    
class CreateDir(SyncEvent):
    def apply(self):
        formatted_path = self.format_path()
        os.makedirs(formatted_path, exist_ok=True)
        logging.info(f"[+] Directory created at: {formatted_path}")

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
        
        formatted_path = self.format_path()
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

class Delete(SyncEvent):
    def purge_directory(self):
        formatted_path = self.format_path()
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
            formatted_path = self.format_path()
            os.remove(formatted_path)
            logging.info(f"[-] File '{formatted_path}' deleted successfully.")
            file_entry = session.query(File).filter_by(path=formatted_path).first()

            if file_entry:
                session.delete(file_entry)
                session.commit()
                logging.info(f"[-] File entry for '{formatted_path}' deleted from database.")
            else:
                logging.error(f"[-] No file entry found for '{formatted_path}' in database.")

class Move(SyncEvent):
    def format_dest_path(self) -> str:
        """Format the destination path using the same logic as format_path()"""
        user = self.metadata['user']
        user_id = session.query(User).filter_by(name=user).first().user_id
        mac_addr = self._get_mac_addr(user)
        raw_path = self.metadata['dest_path']
        logging.info(f"[+] Formatting dest path: {raw_path}")
        dest_path = os.path.normpath(raw_path).replace('\\', '/')
        dest_path = dest_path.split('/')
        dest_path = dest_path[3:]
        dest_path.insert(0, str(mac_addr))
        dest_path.insert(0, str(user_id))
        dest_path.insert(0, '~')
        dest_path = '/'.join(dest_path)       
        formatted_path = os.path.expanduser(dest_path)
        logging.info(f"[+] Formatted dest path: {formatted_path}")
        return formatted_path
    
    def apply(self):
        
        # Format source and destination paths
        src_path = self.format_path()
        dest_path = self.format_dest_path()
        
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

class Modify(SyncEvent):
    def apply(self):
        formatted_path = self.format_path()
        blocklist = session.query(File).filter_by(path=formatted_path).first()
        logging.info(f"[+] Blocklist entry found for file: {formatted_path}")
        
        

class Outgoing(Sync):
    def __init__(self):
        super().__init__()
        pass
if __name__ == "__main__":
    main_thread = threading.Thread(target=main, daemon=True)
    main_thread.start()
    sync_worker_thread = threading.Thread(target=sync_worker)
    sync_worker_thread.start()

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
        for hash, position in self.blocklist:
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
        else:
            logging.error(f"Hash not found in global blocklist: {hash_to_query}")
            return None

class build_instruction():
    def __init__(self):
        pass

    # NOTE: rest of the instruction's such as create/delete/moved can be stored and sent as it was received from client -> server
    # NOTE: event_type = 'created'. just store in sync_queue the instructions for created.
# QUEUE SYSTEM

if __name__ == '__main__':
    global_blocklist_file = "blocklist.json"
    if os.path.exists(global_blocklist_file):
        with open(global_blocklist_file, "r") as file: # Load data from the file if it exists
            global_blocklist = json.load(file)
    else:
        global_blocklist = {}
    logging.info(f'INITIALISING global_blocklist {global_blocklist}')

ip_file = "ip_map.json"
if os.path.exists(ip_file):
    with open(ip_file, "r") as file: # Load data from the file if it exists
        ip_map = json.load(file)
else:
    ip_map = {
        "users": {}
    } # NOTE: it dont create the file just yet, create the varible. 
    # when stuff is being added to the varible, the file will be created then.
logging.info(f'INITIALISING ip_map: {ip_map}')

invites_file = "invites.json"
if os.path.exists(invites_file):
    with open(invites_file, "r") as file: # Load data from the file if it exists
        invites = json.load(file)
else:
    invites = {
        "folders": {},
        "groups": {}
    }
logging.info(f'INITIALISING invites: {invites}')

# NOTE: all these are dictionaries therefore automatically global variables