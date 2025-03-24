from flask import Flask, render_template
from flask_socketio import SocketIO

from flask_socketio import send, emit
from flask_socketio import join_room, leave_room

import threading
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

def ack():
    print('message was received!')

@socketio.on('my event')
def handle_my_custom_event(json):
    print('received json: ' + str(json))

@socketio.on('message')
def handle_message(message):
    send(message, namespace='/chat')

@socketio.on('json')
def handle_json(json):
    send(json, json=True)

@socketio.on('join')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    send(username + ' has entered the room.', to=room)

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    send(username + ' has left the room.', to=room)

@socketio.on('change message')
def change_message():
    x = input('change message?')
    print('changing message')
    emit('message',x, broadcast=True)

def some_function():
    print('some function')
    socketio.emit('message','hello')

if __name__ == '__main__':

    socket = threading.Thread(target=socketio.run, args=(app,))
    socket.start()
    print('running')

    time.sleep(3)
    # x = input('change message?')
    # socketio.emit('message',x)
    socketio.emit('message','hello')
    print('ran')
    