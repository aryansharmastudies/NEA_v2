var socket = io();
socket.on('connect', function() {
    socket.emit('my event', {data: 'I\'m connected!'}); // emit an event to the server
});

function changemsg() {
    socket.emit('change message'); // emit an event to the server
}

// Listen for incoming messages from the server
socket.on('message', function(data) {
    var new_msg = data;
    document.getElementById('msg').innerText = new_msg;
});