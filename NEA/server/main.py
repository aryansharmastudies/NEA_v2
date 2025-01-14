from sqlalchemy import URL, create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
import socket
import json
import logging
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
    __annotations__ = 'folders'

    folder_id = Column(String, primary_key=True)
    name = Column(String)
    mac_addr = Column(String, primary_key=True)
    path = Column(String)
    type = Column(String)
    size = Column(Integer)

Base.metadata.create_all(engine)
########## CRUD(create, read, update, delete) ####
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

########## SOCKETS ###############################
def handle_client_message(message):
    try:
        data = json.loads(message)  # Parse JSON message
        action = data.get('action')
        if action == 'ping':
            logging.info(f'Received ping from {data['ip_addr']}')
            clientsocket.send('pong'.encode('utf-8'))
            logging.info(f'Pong sent to {data['ip_addr']}')
        
        elif action == 'login':
            l_user = data['l_user']
            hash = data['hash']
            status = login(l_user, hash)
            logging.info(f'Sending login status: {status}')
            clientsocket.send(str(status).encode('utf-8'))
            
        elif action == 'register_user':
            r_user = data['r_user']
            hash = data['hash']
            status = create_user(r_user, hash)
            logging.info(f'Sending registration status: {status}')
            clientsocket.send(str(status).encode('utf-8'))
        
        elif action == 'add_device':
            mac_addr = data['mac_addr']
            device_name = data['r_dev_name']
            username = data['user']
            status = create_device(username, device_name, mac_addr)
            logging.info(f'Sending device status: {status}')
            clientsocket.send(str(status).encode('utf-8'))

        elif action == 'send_file':
            filename = data['filename']
            username = data['username']
            file_size = data['file_size']
            print(f'Preparing to receive file: {filename} ({file_size} bytes) from {username}')
            # TODO File receiving logic here

        elif action == 'remove_user':
            username = data['username']
            print(f'Removing user: {username}')
            # Remove user logic here

        else:
            print('Unknown action!')
    except json.JSONDecodeError:
        print('Invalid JSON received.')
    except KeyError as e:
        print(f'Missing field: {e}')

# Example server loop
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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