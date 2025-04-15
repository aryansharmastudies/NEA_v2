# observer - observers/monitor directory or files
# within a directory there are certail events that can happen
# any time event happens, observer can see it 

# observers
# handler
# event 

import sys
import time
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler # several which we can use
import logging
import shutil
import os
#class Handler(PatternMatchEventHandler):
#    def __init__(self) -> None:

# 🔴if the size of folder reaches a particular limit you can make a backup.🔴
def on_modified(event):
    print('yippee')
    backup_path = '/Users/aryan/Desktop/backup/'
    for file_name in os.listdir(path):
        # construct fill file path
        source = path + file_name
        destination = backup_path + file_name

        print(f' source {source}')
        print(f' destination {destination}')
        # copy the file
        if os.path.isfile(source):
            shutil.copy(source, destination)
            print(f'File {file_name} copied to {backup_path}')

class Handler(PatternMatchingEventHandler):
    def __init__(self) -> None:
        PatternMatchingEventHandler.__init__(self, patterns=['*.csv'],
       ignore_directories=True, case_sensitive=False)
    
    def on_created(self,event):
        print("A new create event was made",event.src_path)

    def on_modified(self,event):
        print("A new modified event was made",event.src_path)

    def on_deleted(self,event):
        print("A deletion event was made",event.src_path)




if __name__ == '__main__':
    logging.basicConfig(filename='dev.log',filemode='a',level=logging.INFO, format='%(asctime)s - %(process)d - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    logging.info("Starting the observer...")

    path = sys.argv[1] if len(sys.argv) > 1 else '.' # '.' means current directory
    
    event_handler = LoggingEventHandler()
    event_handler.on_modified = on_modified # when file is modified, call this function
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()

 