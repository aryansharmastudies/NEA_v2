from sqlalchemy import URL, create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
import socket
from get_wip import *
from get_lip import *
from sqlalchemy.orm import sessionmaker
########## IP ADDRESS ############################
# NOTE - gets the ip. hash the one you don't want.
#ip = l_wlan_ip()
ip = w_wlan_ip()
print(ip)
##################################################
########## DATA BASE #############################
db_url = "sqlite:///database/database.db"
engine = create_engine(db_url)
Base = declarative_base()

Session = sessionmaker(bind=engine)
session = Session() # returns Session object upon which we can perform action.

class User(Base):
    __tablename__ = 'users'

    user_id = Column(Integer, primary_key=True)
    name = Column(String)
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
#create_user("Aryan", "aryanbvn@gmail.com")
def create_device(user_id, name, mac_addr): # NOTE: user_id will be passed in by the user, when adding a new device.
    device = Device(user_id=user_id, name=name, mac_addr=mac_addr)
    session.add(device)
    session.commit()
#create_device(1,"osaka", "123.456.789")
##################################################
########## SOCKETS ###############################
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(socket.gethostname())
s.bind((ip, 8000))
s.listen(10)
while True:
    clientsocket, addr = s.accept()
    print(f"connected with {addr}")
    message = clientsocket.recv(1024).decode('utf-8')
    if message == 'ping':
        clientsocket.send(f"active".encode('utf-8'))
    print(message)
    clientsocket.close()
    # TODO store info in db
##################################################


