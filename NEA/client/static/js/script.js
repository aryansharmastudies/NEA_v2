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
});

closeFolderBtn.addEventListener('click', () => {
    modalFolder.classList.remove('open');
});
