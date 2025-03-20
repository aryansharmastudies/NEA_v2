<script>
    var socket = io()
    socket.on('connect', function(){
        socket.emit('connect', {data: 'Connection request from Front-end.'})
    });

    socket.on('alerts', function(alerts){
        // Loop through the alerts array and create a new alert div for each
        for (let alert of alerts) {
            // Create the alert div element
            let alertDiv = document.createElement('div');
            alertDiv.classList.add('alert');
            
            // Add the close button
            let closeButton = document.createElement('span');
            closeButton.classList.add('closebtn');
            closeButton.innerHTML = '&times;';
            closeButton.onclick = function() {
                this.parentElement.style.display = 'none'; // Hide the alert when clicked
            };
            
            // Add the alert message text
            alertDiv.innerHTML = alert;
            
            // Append the close button to the alert
            alertDiv.prepend(closeButton);
            
            // Append the alert div to the body or any other container
            document.body.appendChild(alertDiv);
        }
    })
</script>