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
    const sharingContent = document.getElementById("sharing");

    // Clear existing content
    sharingContent.innerHTML = "<h3>Sharing Settings</h3>";

    // Display raw JSON data as a string
    sharingContent.innerHTML += `<pre>${JSON.stringify(data, null, 2)}</pre>`;
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