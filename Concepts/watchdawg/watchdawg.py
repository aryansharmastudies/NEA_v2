import time

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
import json
import os

import threading

with open('dir.json', 'r') as fp:
    data = json.load(fp)
    dirs =[]
    for dir in data:
        dirs.append(dir)

print(dirs)
class MyEventHandler(FileSystemEventHandler):
    #def on_any_event(self, event: FileSystemEvent) -> None:
    #    print(event)

    def on_moved(self, event):
        print(f'🟣 {event}') # 💥
    def on_created(self, event):
        print(f'🟢 {event.src_path} has been {event.event_type}') # 💥
    def on_deleted(self, event):
        print(f'🔴 {event.src_path} has been {event.event_type}') # 💥
    def on_modified(self, event):
        stats = os.stat(event.src_path)
        if event.is_directory == True:
            pass
        else:
            print(f'🟡 {event.src_path} has been {event.event_type}. Current size {stats.st_size} bytes') # 💥
            print(f'File size: {stats.st_size} bytes')  # Added to log file size
            print(f'Last modified: {time.ctime(stats.st_mtime)}')  # Added to log last modified time
    # def on_closed(self, event):
        # print(f'🔵 {event}')

# filemovedevent = FileSystemEvent()

# event_handler = MyEventHandler()
# observer = Observer()
# observer.schedule(event_handler, ".", recursive=True)
# observer.start()
# try:
#     while True:
#         time.sleep(1)
# finally:
#     observer.stop()
#     observer.join()

def start_watchdog(dirs):
    event_handler = MyEventHandler()
    N2watch = Observer()
    threads = []

    for d in dirs:
        targetPath = str(d)
        N2watch.schedule(event_handler, targetPath, recursive=True)
        threads.append(N2watch)

    N2watch.start()

    try:
        while True:
                time.sleep(1)
    except KeyboardInterrupt:
        N2watch.stop()
    N2watch.join()

if __name__ == "__main__":
    watchdog = threading.Thread(target=start_watchdog, args=(dirs,))
    watchdog.start()
    # observer = Observer()
    # observer.schedule(event_handler, ".", recursive=True)
    # observer.start()
    # try:
    #     while True:
    #         time.sleep(1)
    # finally:
    #     observer.stop()
    #     observer.join()