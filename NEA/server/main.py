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

########## LOGGING ##############################
def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='basic.log',)
main()
########## IP ADDRESS ############################
# NOTE - gets the ip. hash the one you don't want.
system = input('windows(w) or linux(l)?')
if system == 'w':
    ip = w_wlan_ip()
else:
    ip = l_wlan_ip()
print(ip)
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

def create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type):
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

    for shared_user in shared_users:  # 😳😿
        # find the shared_user and its devices MAC ADDRESS
        # check if it exists in ip_map.json
        # then send a ping first
        # then followed by a request, if pong is returned

        shared_user = shared_user.split(':')
        username = shared_user[0]
        device_name = shared_user[1]
        user = session.query(User).filter_by(name=username).first()
        target_user_id = user.user_id
        if not user:
            logging.info(f'User: {username} not found')
            return json.dumps({'status': '404', 'status_msg': 'User not found'})
        
        logging.info(f'User: {username} found with User_ID: {target_user_id}')
        device = session.query(Device).filter_by(user_id=target_user_id, name=device_name).first()
        
        if not device:
            logging.info(f'Device: {device_name} not found for User: {username}')
            return json.dumps({'status': '404', 'status_msg': 'Device not found'})
        
        device_mac_addr = device.mac_addr # gets devices mac addr
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
        logging.info(f'Sending ping to {username} with ip: {ip}')

        status = send(json.dumps({'action': 'ping'}), ip, 6000) # sends a ping through!
        if status == '400': # if ping fails
            logging.info(f'Ping failed for {username} with ip: {ip}')
            # adds to invites.json
            if username not in invites["folders"]: # first check if the user is in the invites file
                invites["folders"][username] = {} # if not, add them
            invites["folders"][username][folder_id] = {'folder_label': folder_label}
            
            with open(invites_file, "w") as file:
                json.dump(invites, file, indent=2)
         
            
            # ❗no need to return if user is offline, as the user will get the invite when they log in.
            # return json.dumps({'status': '400', 'status_msg': 'Ping failed'})
        else: # if ping is successful
            logging.info(f'Ping successful for {username} with ip: {ip}')
            data = send(json.dumps({'action': 'add_folder', 'folder_label': folder_label, 'folder_id': folder_id}), ip, 6000)
            if data != False:
                data = json.loads(data)
                directory = data['directory']
                shared_user = Share(folder_id=folder_id, mac_addr=mac_addr, path=directory)
                session.add(shared_user) # im sure with a for loop you can itterate and add many 'share' objects to the session, then commit them.
            else:
                logging.info(f'data {username} sent has failed: {data}')
    # use async to ask the currently active users
    # or else, put instruction in a json file!!!
    # and whenever user logs in, check if they are in the file.

    folder = Folder(mac_addr=mac_addr, name=folder_label, folder_id=folder_id, path=directory, type=folder_type)
    session.add(folder)
    session.commit()

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
    
ip_file = "ip_map.json"
if os.path.exists(ip_file):
    with open(ip_file, "r") as file: # Load data from the file if it exists
        ip_map = json.load(file)
else:
    ip_map = {
        "users": {}
    } # NOTE: it dont create the file just yet, create the varible. 
    # when stuff is being added to the varible, the file will be created then.

invites_file = "invites.json"
if os.path.exists(invites_file):
    with open(invites_file, "r") as file: # Load data from the file if it exists
        invites = json.load(file)
else:
    invites = {
        "folders": {},
        "groups": {}
    }
                                                                                                                                                                                                                                                                                                                                   
def track_ip(user, mac_addr, ip):
    if user not in ip_map["users"]:
        ip_map["users"][user] = {}
    mac_addr = str(mac_addr)
    ip_map["users"][user][mac_addr] = ip
    logging.info(f'ip_map: {ip_map}')

    with open(ip_file, "w") as file:
        json.dump(ip_map, file, indent=2)
    
    return json.dumps({'status': '200', 'status_msg': 'IP updated successfully'})
        
########## SOCKETS ###############################
def send(message, ip, port):
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        c.connect((ip, port))
    except: 
        return '400' 
    c.send(message.encode('utf-8'))
    client_data = c.recv(1024).decode('utf-8')
    client_data = json.loads(client_data)
    status_code = client_data.get('status_code', False)
    status_msg = client_data.get('status_msg', False)
    data = client_data.get('data', False)

    if message['action'] == 'ping':
        return status_code
    elif message['action'] == 'add_folder':
        return data 



def handle_client_message(message):
    #NOTE 'status' here includes both the status-code and status-description e.g. 
    # {'status': '201', 'status_msg': 'Device added successfully'}
    try:
        client_data = json.loads(message)  # Parse JSON message
        action = client_data.get('action')
    except json.JSONDecodeError:
        print('Invalid JSON received.')
    except KeyError as e:
        print(f'Missing field: {e}')

    if action == 'ping':
        logging.info(f'Received ping from {client_data['ip_addr']}')
        clientsocket.send('pong'.encode('utf-8'))
        logging.info(f'Pong sent to {client_data['ip_addr']}')

    elif action == 'track':
        ip_addr = client_data['ip_addr']
        user = client_data['user']
        mac_addr = client_data['mac_addr']
        logging.info(f'Recieved tracking info from {user} with ip_addr {ip_addr} and mac_addr {mac_addr}')
        status = track_ip(user, mac_addr, ip_addr)
        clientsocket.send(str(status).encode('utf-8'))

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

    elif action == 'add_folder': # TODO get it working.
        logging.info(f'Recieved data to add folder: {client_data}')
        mac_addr = client_data['mac_addr']
        folder_label = client_data['folder_label']
        folder_id = client_data['folder_id']
        directory = client_data['directory']
        shared_users = client_data['shared_users']
        folder_type = client_data['folder_type']
        status = create_folder(mac_addr, folder_label, folder_id, directory, shared_users, folder_type)
        logging.info(f'Sending folder status: {status}')
        clientsocket.send(str(status).encode('utf-8'))

    elif action == 'remove_user': # TODO should be a potential option for admin.
        username = client_data['username']
        print(f'Removing user: {username}')
        # Remove user logic here

    elif action == 'request':
        requested_data = client_data['data']
        response = Data_Response(requested_data) # response is the object made.
        response.scrape()
        response_in_json = response.tojson()
        logging.info(f'SENDING: {response_in_json}')
        clientsocket.send(str(response_in_json).encode('utf-8')) # converted to JSON using 'tojson'.
        del response

    else:
        print('Unknown action!')
    

# SERVER LOOP
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
    handle_client_message(message)
    
    clientsocket.close()