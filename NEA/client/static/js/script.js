var socket = io();

var user_device_data = "";

socket.on('connect', function() {
    console.log("Connected to WebSocket");
}); 

socket.on('wtf', function() {
    console.log("wtf"); 
});

// Listen for alerts
socket.on('alerts', function(data) {
    document.getElementById('alert_box').innerText = data;
});
socket.on('users_devices_data', function(data) {
    console.log("Received users and devices data:", data);
    user_device_data = data; });



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

