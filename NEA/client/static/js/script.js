var socket = io();
//var socket = io.connect(window.location.origin);

var user_device_data = "";
var folder_data = "";
var alerts = "";

socket.on('connect', function() {
    console.log("Connected to WebSocket");
}); 

// Listen for alerts
socket.on('alerts', function(data) {
    document.getElementById('alert_box').innerText = data;
    alerts = data;
    console.log("Received alert:", alerts);
});
socket.on('users_devices_data', function(data) {
    console.log("Received users and devices data:", data);
    user_device_data = data; 
});

socket.on('folder_data', function(data) {
    console.log('Received folder_data:', data);
    folder_data = data;
});




// Register Device Modal
const openDeviceBtn = document.getElementById('openModalDevice');
const closeDeviceBtn = document.getElementById('closeModalDevice');
const modalDevice = document.getElementById('modalDevice');

openDeviceBtn.addEventListener('click', () => {
    modalDevice.classList.add('open');
});

closeDeviceBtn.addEventListener('click', () => {
    modalDevice.classList.remove('open');
});

// socket.on('users_devices_data', function(data) {
//     console.log("Received users and devices data:", data);
//     if (data.error) {
//         console.error("Error received:", data.error);
//         // Show error to user
//         const sharingForm = document.getElementById("sharingForm");
//         if (sharingForm) {
//             sharingForm.innerHTML = `<p class="error">Error loading data: ${data.error}</p>`;
//         }
//     } else {
//         console.log("Received users and devices data:", data);
//         if (Object.keys(data).length === 0) {
//             // Handle empty data case
//             const sharingForm = document.getElementById("sharingForm");
//             if (sharingForm) {
//                 sharingForm.innerHTML = "<p>No users or devices available</p>";
//             }
//         } else {
//             // Make sharingForm a global variable at the top of your file
//             sharingForm = document.getElementById("sharingForm");
//             displayRawData(data);
//         }
//     }
// });

// Modal button logic
const openFolderBtn = document.getElementById('openModalFolder');
const closeFolderBtn = document.getElementById('closeModalFolder');
const modalFolder = document.getElementById('modalFolder');

openFolderBtn.addEventListener('click', () => {
    modalFolder.classList.add('open');
    console.log("openFolderBtn clicked");
    socket.emit('request_users_devices');
    displayRawData(user_device_data)  // ✅ Emit WebSocket event instead of fetch
});

closeFolderBtn.addEventListener('click', () => {
    modalFolder.classList.remove('open');
});

// Render data
function displayRawData(user_device_data) {
    const sharingForm = document.getElementById("sharingForm");
    sharingForm.innerHTML = "";

    for (const [user, devices] of Object.entries(user_device_data)) {
        const userHeading = document.createElement("h4");
        userHeading.textContent = user;
        sharingForm.appendChild(userHeading);

        devices.forEach((device) => {
            const container = document.createElement("div");

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.name = "selected_devices";
            checkbox.value = `${user}:${device}`;
            checkbox.id = device;

            const label = document.createElement("label");
            label.htmlFor = device;
            label.textContent = device;

            container.appendChild(checkbox);
            container.appendChild(label);
            sharingForm.appendChild(container);
        });
    }
}

// Tab functionality
const tablinks = document.querySelectorAll(".tablink");
const tabcontents = document.querySelectorAll(".tabcontent");

tablinks.forEach((tab) => {
    tab.addEventListener("click", () => {
        const tabName = tab.getAttribute("data-tab");

        // Remove active class from all tabs and content
        tablinks.forEach((t) => t.classList.remove("active"));
        tabcontents.forEach((c) => c.classList.remove("active"));

        // Add active class to the clicked tab and corresponding content
        tab.classList.add("active");
        document.getElementById(tabName).classList.add("active");
    });
});

function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
}

function validateGeneralForm() {
    let isValid = true;
    const folderLabel = document.getElementById("folder_label").value.trim();
    const folderId = document.getElementById("folder_id").value.trim();
    const folderPath = document.getElementById("folder_path").value.trim();

    if (!folderLabel) {
        showError("folder_label_error", "Folder label is required.");
        isValid = false;
    } else {
        showError("folder_label_error", "");
    }

    if (!folderId) {
        showError("folder_id_error", "Folder ID is required.");
        isValid = false;
    } else {
        showError("folder_id_error", "");
    }

    if (!folderPath) {
        showError("folder_path_error", "Folder path is required.");
        isValid = false;
    } else {
        showError("folder_path_error", "");
    }

    return isValid;
}

// Function to collect data from all forms and submit it
function submitAllForms() {
    // Validate the General tab form
    if (!validateGeneralForm()) {
        return; // Stop if validation fails
    }

    // Collect data from the General tab
    const generalForm = document.getElementById("generalForm");
    const generalData = new FormData(generalForm);

    // Collect data from the Sharing tab
    const sharingForm = document.getElementById("sharingForm");
    const sharingData = new FormData(sharingForm);

    // Collect data from the Advanced tab
    const advancedForm = document.getElementById("advancedForm");
    const advancedData = new FormData(advancedForm);

    // Combine all data into a single JSON object
    const combinedData = {
        action: generalData.get("action"),
        folder_label: generalData.get("folder_label"), // will be filled
        folder_id: generalData.get("folder_id"), // will be filled
        directory: generalData.get("folder_path"), // will be filled
        shared_users: Array.from(sharingData.getAll("selected_devices")), // Get all selected devices(might not be filled!)
        folder_type: advancedData.get("folder_type") // will be filled
    };

    // Send the combined data to the server
    fetch("/submit_folder", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(combinedData)
    })
    .then((response) => response.json())  // Convert response to JSON
    .then((data) => {
        console.log("Response from server:", data);
    
        // Show success or failure message based on response
        if (data.status === "success") {
            alert("✅ " + data.message); // Folder added successfully
        } else {
            alert("❌ " + data.message); // Folder not added
        }
    })
    .catch((error) => {
        console.error("Error:", error);
        alert("An error occurred. Please try again.");
    });
}

// Add event listener to the Submit button
document.getElementById("submitAllForms").addEventListener("click", (event) => {
    event.preventDefault(); // Prevent the default form submission
    submitAllForms(); // Call the function to submit all forms
});


// Get current device MAC address
function getCurrentMacAddress() {
    return document.body.getAttribute('data-mac-address') || '';
}

// Format file path to show only the last part if it's too long
function formatPath(path) {
    if (path.length > 30) {
        const parts = path.split('/');
        return '...' + path.slice(path.length - 30);
    }
    return path;
}

// Modify the renderFolders function to handle both array and object formats
function renderFolders(folderData) {
    console.log('Rendering folders with data:', folderData);
    const foldersContainer = document.getElementById('folders-container');
    if (!foldersContainer) return;
    
    // Clear previous content
    foldersContainer.innerHTML = '';
    
    // Check if we have folder data
    if (!folderData || !folderData.folders || folderData.folders.length === 0) {
        foldersContainer.innerHTML = '<p>No folders found. Add a folder to get started.</p>';
        return;
    }
    
    const currentMacAddress = getCurrentMacAddress();
    
    // Loop through each folder
    folderData.folders.forEach(folder => {
        // Extract folder data - handle both array and object formats
        let macAddress, folderId, folderName, folderPath, folderType;
        
        if (Array.isArray(folder)) {
            // Handle array format [macAddress, folderId, folderName, folderPath, folderType]
            [macAddress, folderId, folderName, folderPath, folderType] = folder;
        } else {
            // Handle object format {mac_addr, folder_id, name, path, type}
            macAddress = folder.mac_addr;
            folderId = folder.folder_id;
            folderName = folder.name;
            folderPath = folder.path;
            folderType = folder.type;
        }
        
        // Create folder box
        const folderBox = document.createElement('div');
        folderBox.className = 'folder-box';
        folderBox.classList.add(macAddress === currentMacAddress ? 'current-device' : 'other-device');
        
        // Create folder name element
        const nameElement = document.createElement('div');
        nameElement.className = 'folder-name';
        nameElement.textContent = folderName;
        
        // Create folder details container
        const detailsContainer = document.createElement('div');
        detailsContainer.className = 'folder-details';
        
        // Add folder attributes
        detailsContainer.innerHTML = `
            <div class="folder-attribute"><strong>ID:</strong> ${folderId}</div>
            <div class="folder-attribute"><strong>Path:</strong> ${formatPath(folderPath)}</div>
            <div class="folder-attribute"><strong>Type:</strong> ${folderType}</div>
            <div class="folder-attribute"><strong>Device:</strong> ${macAddress}</div>
        `;
        
        // Create edit button
        const editButton = document.createElement('button');
        editButton.className = 'edit-icon';
        editButton.innerHTML = '✏️';
        editButton.setAttribute('aria-label', 'Edit folder');
        
        // Add event listeners
        folderBox.addEventListener('click', (e) => {
            // Only toggle if we didn't click the edit button
            if (e.target !== editButton) {
                detailsContainer.classList.toggle('expanded');
            }
        });
        
        editButton.addEventListener('click', (e) => {
            e.stopPropagation(); // Prevent folder box click event
            openDeleteModal(folderId, folderName);
        });
        
        // Append elements to folder box
        folderBox.appendChild(nameElement);
        folderBox.appendChild(detailsContainer);
        folderBox.appendChild(editButton);
        
        // Add folder box to container
        foldersContainer.appendChild(folderBox);
    });
}

// Function to open the delete folder modal
function openDeleteModal(folderId, folderName) {
    const modal = document.getElementById('deleteFolderModal');
    const folderNameSpan = document.getElementById('folderToDelete');
    
    // Update modal content
    folderNameSpan.textContent = folderName;
    
    // Store folder ID for delete confirmation
    document.getElementById('confirmDeleteFolder').setAttribute('data-folder-id', folderId);
    
    // Show modal
    modal.classList.add('open');
}

// Function to delete a folder
function deleteFolder(folderId) {
    fetch("/delete_folder", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ 
            action: "delete_folder",
            folder_id: folderId 
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "success") {
            // Refresh folder display
            socket.emit('request_folders');
            alert("✅ Folder deleted successfully");
        } else {
            alert("❌ Error: " + data.message);
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("An error occurred while deleting the folder");
    });
}

// Set up event listeners when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initial folder rendering if data is available
    if (folder_data && folder_data.folders) {
        renderFolders(folder_data);
    }
    
    // Set up delete modal event listeners
    const confirmDeleteBtn = document.getElementById('confirmDeleteFolder');
    const cancelDeleteBtn = document.getElementById('cancelDeleteFolder');
    const deleteFolderModal = document.getElementById('deleteFolderModal');
    
    if (confirmDeleteBtn) {
        confirmDeleteBtn.addEventListener('click', () => {
            const folderId = confirmDeleteBtn.getAttribute('data-folder-id');
            deleteFolder(folderId);
            deleteFolderModal.classList.remove('open');
        });
    }
    
    if (cancelDeleteBtn) {
        cancelDeleteBtn.addEventListener('click', () => {
            deleteFolderModal.classList.remove('open');
        });
    }
    
    // Listen for folder data updates from WebSocket
    socket.on('folder_data', function(data) {
        console.log('Received folder_data:', data);
        folder_data = data;
        renderFolders(data);
    });
    
    // Request folders when loading the page
    socket.emit('request_folders');
});


// Alert box handling for share requests
socket.on('alerts', function(data) {
    document.getElementById('alert_box').innerText = "System online";
    alerts = data;
    console.log("Received alert:", alerts);
    
    // Process and display alert boxes
    processShareRequests(alerts);
});

function processShareRequests(alerts) {
    const container = document.getElementById('share-requests-container');
    
    // Clear existing alerts
    container.innerHTML = '';
    
    if (!alerts || alerts.length === 0) {
        return;
    }
    
    // Create an alert box for each share request
    alerts.forEach((alert, index) => {
        const [folderId, folderName, deviceName] = alert;
        
        // Create alert box
        const alertBox = document.createElement('div');
        alertBox.className = 'share-request';
        alertBox.setAttribute('data-index', index);
        alertBox.setAttribute('data-folder-id', folderId);
        alertBox.setAttribute('data-folder-name', folderName);
        alertBox.setAttribute('data-device-name', deviceName);
        
        // Create message
        const message = document.createElement('div');
        message.className = 'share-request-message';
        message.textContent = `Device "${deviceName}" wants to share the folder "${folderName}" with you`;
        
        // Create buttons container
        const buttons = document.createElement('div');
        buttons.className = 'share-request-buttons';
        
        // Accept button
        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'accept-button';
        acceptBtn.textContent = 'Accept';
        acceptBtn.addEventListener('click', () => showAcceptModal(folderId, folderName, deviceName, index));
        
        // Decline button
        const declineBtn = document.createElement('button');
        declineBtn.className = 'decline-button';
        declineBtn.textContent = 'Decline';
        declineBtn.addEventListener('click', () => handleDeclineShare(folderId, deviceName, index));
        
        // Ignore button
        const ignoreBtn = document.createElement('button');
        ignoreBtn.className = 'ignore-button';
        ignoreBtn.textContent = 'Ignore';
        ignoreBtn.addEventListener('click', () => handleIgnoreShare(index));
        
        // Assemble the alert box
        buttons.appendChild(acceptBtn);
        buttons.appendChild(declineBtn);
        buttons.appendChild(ignoreBtn);
        
        alertBox.appendChild(message);
        alertBox.appendChild(buttons);
        
        container.appendChild(alertBox);
    });
}

function showAcceptModal(folderId, folderName, deviceName, index) {
    // Get the modal
    const modal = document.getElementById('acceptShareModal');
    
    // Set hidden fields
    document.getElementById('share-request-id').value = index;
    document.getElementById('share-folder-id').value = folderId;
    document.getElementById('share-device-name').value = deviceName;
    
    // Set suggested values
    document.getElementById('share-folder-label').value = folderName;
    
    // Create suggested path (~/Shared/[folderName])
    const suggestedPath = `~/Shared/${folderName}`;
    document.getElementById('share-folder-path').value = suggestedPath;
    
    // Show the modal
    modal.classList.add('open');
}

function handleDeclineShare(folderId, deviceName, index) {
    fetch('/decline_share', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            folder_id: folderId,
            device_name: deviceName,
            index: index
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            // Remove this alert from the alerts array
            alerts.splice(index, 1);
            
            // Refresh the alert boxes
            processShareRequests(alerts);
        } else {
            console.error('Failed to decline share:', data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function handleIgnoreShare(index) {
    // Just hide this specific alert
    const alertBox = document.querySelector(`.share-request[data-index="${index}"]`);
    if (alertBox) {
        alertBox.style.display = 'none';
    }
}

// Set up event listeners for the Accept Share Modal
document.addEventListener('DOMContentLoaded', function() {
    const acceptShareForm = document.getElementById('acceptShareForm');
    const cancelAcceptShare = document.getElementById('cancelAcceptShare');
    const acceptShareModal = document.getElementById('acceptShareModal');
    
    if (acceptShareForm) {
        acceptShareForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = {
                index: document.getElementById('share-request-id').value,
                folder_id: document.getElementById('share-folder-id').value,
                device_name: document.getElementById('share-device-name').value,
                folder_label: document.getElementById('share-folder-label').value,
                folder_path: document.getElementById('share-folder-path').value
            };
            
            fetch('/accept_share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    // Remove this alert from the alerts array
                    alerts.splice(parseInt(formData.index), 1);
                    
                    // Refresh the alert boxes
                    processShareRequests(alerts);
                    
                    // Close the modal
                    acceptShareModal.classList.remove('open');
                } else {
                    console.error('Failed to accept share:', data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }
    
    if (cancelAcceptShare) {
        cancelAcceptShare.addEventListener('click', function() {
            acceptShareModal.classList.remove('open');
        });
    }
});