import os
from time import sleep

file_metadata = {} # [file_metadata is a dictionary which stores all the files it knows and its last modified time and size] 

def check_for_changes(directory):
    global file_metadata
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            stats = os.stat(filepath)
            mtime, size = stats.st_mtime, stats.st_size
            if filepath not in file_metadata or file_metadata[filepath] != (mtime, size): # checks if the file is in file_metadata dictionary, if not => add it to the dictionary. 
                # if it is, check if the last modified time and size is the same as the one in the dictionary. If not => print the file path, last modified time and size
                file_metadata[filepath] = (mtime, size)
                print(f"File changed: {filepath}, {mtime}, {size}")

while True:
    check_for_changes(r"N:\NEA_v2\scratch")
    sleep(1)  # Check every second (adjust as needed)
