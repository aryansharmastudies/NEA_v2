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
ip = l_wlan_ip()
#ip = w_wlan_ip()
#################################################
########## FLASK ################################
app = Flask(__name__)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite3'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(minutes=3) # session will last for 10 days.
#################################################
########## DATA BASE ############################
db = SQLAlchemy(app)

class servers(db.Model):
    name = db.Column(db.String(100), primary_key=True)

    def __init__(self, name):
        self.name = name
#################################################
########## WEBSITE ##############################
@app.route('/pair', methods=['POST','GET'])
def pair():
    if request.method == 'POST':
        session.permanent = True
        server_name = request.form['nm'] # nm is dictionary key.
        logging.info(f'server_name: {server_name}')
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try: 
            s.connect((server_name, 8000))
            s.send(f'ping'.encode('utf-8'))
            if s.recv(1024).decode('utf-8') == 'active':
                logging.info(f"status: active")
                session['server_name']=server_name
                
                found_server = servers.query.filter_by(name=server_name).first()
                logging.info(f'found_server: {found_server}')
                if found_server:
                    flash(f'Reconnected!', 'info')
                    return redirect(url_for('dashboard'))
                else:
                    server = servers(server_name)
                    db.session.add(server)
                    db.session.commit()
                
                flash(f'Connected!', 'info')
                return redirect(url_for('dashboard'))
            else:
                flash(f'Server inactive, please retry!', 'info')
                return redirect(url_for('pair'))
        except: 
            flash(f'Could not connect to server!', 'info')
            return redirect(url_for('pair'))
    else:
        if 'server_name' in session:
            flash('Already Connected!', 'info')
            return redirect(url_for('dashboard'))
        
        return render_template('pair.html')
    
    # DONE: if the user is already connected to a pi and in a session, redirect to dashboard page.
    # DONE: do a GET request and get the hostname to connect to.
    # TODO: then try establish a connection and display it onto the page.

@app.route('/dashboard')
def dashboard():
    if 'server_name' in session:
        return render_template('dashboard.html', server_name=session['server_name']) # pass in server_name to the dashboard.html file.
    else:
        flash('You are not connected to a server!', 'info')
        return render_template('pair.html')
@app.route("/unpair")
def logout():
    if "server_name" in session:
        server_name = session["server_name"]
        flash(f"{server_name} has been unpaired!", "info")
    session.pop("server_name", None)
    return redirect(url_for('pair'))
#################################################
########## LOGGING ##############################
def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="basic.log",)
    
#################################################
########## ADDING USER ##########################
def add_user(name, email):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('osaka', 8000))
    s.send(f"{name}:{email}".encode('utf-8'))
#################################################
if __name__ == "__main__":
    main()
    with app.app_context():
        db.create_all()
    app.run(debug=True)