from sqlalchemy import URL, create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
import socket
import json
import logging
from get_wip import *
from get_lip import *
from sqlalchemy.orm import sessionmaker

########## IP ADDRESS ############################
# NOTE - gets the ip. hash the one you don't want.
ip = l_wlan_ip()
#ip = w_wlan_ip()
logging.info(f"IP Address: {ip}")

########## DATABASE SETUP ############################
db_url = 'sqlite:///database/database.db'
engine = create_engine(db_url)
Base = declarative_base()

Session = sessionmaker(bind=engine)
session = Session()

# Define User and Device tables
class User(Base):
    __tablename__ = 'users'
    user_id = Column(Integer, primary_key=True)
    name = Column(String)
    hash = Column(String)
    email = Column(String)

class Device(Base):
    __tablename__ = 'devices'
    user_id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String)
    mac_addr = Column(String, primary_key=True)

########## LOGGING SETUP ##############################
def log() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename='sexy.log',)
log()    
logging.info("Logging initialized.")

########## CLIENT MESSAGE HANDLER #####################
def handle_client_message(message, clientsocket):
    try:
        data = json.loads(message)  # Parse JSON message
        action = data.get('action')

        if action == 'ping':
            logging.info('Received ping from client.')
            clientsocket.send('pong'.encode('utf-8'))
        
        elif action == 'add_user':
            username = data['r_usr']
            password_hash = data['r_pwd']
            #email = data['email']
            new_user = User(name=username, hash=password_hash, email='default_email')
            session.add(new_user)
            session.commit()
            logging.info(f"Added user: {username}")

        elif action == 'add_device':
            device_id = data['device_id']
            username = data['username']
            logging.info(f"Adding device {device_id} for user {username}")
            # Add device logic here
        
        elif action == 'send_file':
            filename = data['filename']
            username = data['username']
            file_size = data['file_size']
            logging.info(f"Preparing to receive file: {filename} ({file_size} bytes) from {username}")
            # File receiving logic here
        
        elif action == 'remove_user':
            username = data['username']
            logging.info(f"Removing user: {username}")
            # Remove user logic here
        
        else:
            logging.warning("Unknown action received!")
    except json.JSONDecodeError:
        logging.error("Invalid JSON received.")
    except KeyError as e:
        logging.error(f"Missing field in received data: {e}")

########## SOCKET SERVER ##############################
def start_socket_server():
    port = 8000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(10)
    logging.info(f"Socket server running on {ip}:{port}")

    while True:
        clientsocket, address = s.accept()
        logging.info(f"Connection from {address} has been established!")

        try:
            # Receive and handle client message
            message = clientsocket.recv(1024).decode('utf-8')
            handle_client_message(message, clientsocket)
        finally:
            clientsocket.close()

########## MAIN #######################################
def main():
    print("WTF")
    log()
    print("WTF")

    # Initialize the database
    logging.info("Creating database tables...")
    Base.metadata.create_all(engine)
    logging.info("Database tables created successfully.")

    # Start the socket server
    logging.info("Starting the server...")
    start_socket_server()

if __name__ == "__main__":
    print("WTF")
    main()
