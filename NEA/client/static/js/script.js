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

// Add Folder Modal
const openFolderBtn = document.getElementById('openModalFolder');
const closeFolderBtn = document.getElementById('closeModalFolder');
const modalFolder = document.getElementById('modalFolder');

openFolderBtn.addEventListener('click', () => {
    modalFolder.classList.add('open');
    fetchUsersAndDevices(); // Fetch data when modal opens
});

closeFolderBtn.addEventListener('click', () => {
    modalFolder.classList.remove('open');
});

// Function to fetch users and devices
function fetchUsersAndDevices() {
    fetch("/get_users_and_devices") // Flask route to fetch data
        .then((response) => response.json())
        .then((data) => {
            // Display the raw JSON data in the modal
            displayRawData(data); // Call the correct function here
        })
        .catch((error) => {
            console.error("Error fetching data:", error);
        });
}

// Function to display raw JSON data
function displayRawData(data) {
    const sharingForm = document.getElementById("sharingForm");

    // Clear existing content
    sharingForm.innerHTML = "";

    // Iterate through the data and create checkboxes
    for (const [user, devices] of Object.entries(data)) {
        const userHeading = document.createElement("h4");
        userHeading.textContent = user;
        sharingForm.appendChild(userHeading);

        devices.forEach((device) => {
            const checkboxContainer = document.createElement("div");

            const checkbox = document.createElement("input");
            checkbox.type = "checkbox";
            checkbox.name = "selected_devices";
            checkbox.value = `${user}:${device}`; // Store user and device as value
            checkbox.id = device;

            const label = document.createElement("label");
            label.htmlFor = device;
            label.textContent = device;

            checkboxContainer.appendChild(checkbox);
            checkboxContainer.appendChild(label);
            sharingForm.appendChild(checkboxContainer);
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
    .then((response) => response.json())
    .then((data) => {
        console.log("Success:", data);
        alert("Folder added successfully!");
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