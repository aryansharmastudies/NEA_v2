from flask import Flask, redirect, url_for, render_template, request, session, flash, jsonify
from datetime import timedelta # setup max time out session last for.
from flask_sqlalchemy import SQLAlchemy
from uuid import getnode as get_mac
import logging
import socket
import os
from get_wip import *
from get_lip import *

########## IP ADDRESS ###########################
# NOTE - gets the ip. hash the one you don't want.
#ip = l_wlan_ip()
ip = w_wlan_ip()
#################################################
########## FLASK ################################
app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(minutes=5) # session will 

db = SQLAlchemy(app)
#################################################
########## LOGGING ##############################
def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="basic.log",)
    
#################################################
#################################################
def discover_pi():
    pass
#################################################
########## ADDING USER ##########################
def add_user(name, email):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('osaka', 8000))
    s.send(f"{name}:{email}".encode('utf-8'))

add_user("Aryan", "aryan@gmail.com")
#################################################





if __name__ == "__main__":
    main()
    with app.app_context():
        db.create_all()
    app.run(debug=True)