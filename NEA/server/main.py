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
    
#################################################
########## IP ADDRESS ############################
# NOTE - gets the ip. hash the one you don't want.
ip = l_wlan_ip()
#ip = w_wlan_ip()
print(ip)
##################################################
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

Base.metadata.create_all(engine)
##################################################
########## CRUD ##################################
def create_user(name, email):
    user = User(name=name, email=email)
    session.add(user)
    session.commit()
#create_user('Aryan', 'aryanbvn@gmail.com')
def create_device(user_id, name, mac_addr): # NOTE: user_id will be passed in by the user, when adding a new device.
    device = Device(user_id=user_id, name=name, mac_addr=mac_addr)
    session.add(device)
    session.commit()
#create_device(1,'osaka', '123.456.789')
##################################################
########## SOCKETS ###############################
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print(socket.gethostname())
# s.bind((ip, 8000))
# s.listen(10)
# while True:
#     clientsocket, addr = s.accept()
#     print(f'connected with {addr}')
#     message = clientsocket.recv(1024).decode('utf-8')
#     if message == 'ping':
#         clientsocket.send(f'active'.encode('utf-8'))
#     print(message)
#     print(f'closing connection with {addr}')
#     clientsocket.close()
#     # TODO store info in db
##################################################

def handle_client_message(message):
    try:
        data = json.loads(message)  # Parse JSON message
        action = data.get('action')
        if action == 'ping':
            logging.info('Received ping from client', 'info')
            clientsocket.send('pong'.encode('utf-8'))
        
        elif action == 'add_user':
            User(name=data['r_usr'], hash=data['r_pwd'])
            logging.info(f'Adding user: {data['r_usr']} with hash: {data['r_hash']}', 'info')
            # Add user logic here

        elif action == 'login':
            username = data['username']
            password_hash = data['hash']
            print(f'Adding user: {username} with hash: {password_hash}')
        
        elif action == 'add_device':
            device_id = data['device_id']
            username = data['username']
            print(f'Adding device {device_id} for user {username}')
            # Add device logic here

        elif action == 'send_file':
            filename = data['filename']
            username = data['username']
            file_size = data['file_size']
            print(f'Preparing to receive file: {filename} ({file_size} bytes) from {username}')
            # File receiving logic here

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
    clientsocket, address = s.accept()
    print(f'Connection from {address} has been established!')
    
    # Receive data
    message = clientsocket.recv(1024).decode('utf-8')
    handle_client_message(message)
    
    clientsocket.close()