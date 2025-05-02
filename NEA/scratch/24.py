import os
directory = '/home/aryan/Desktop/python/client.txt'
directory = directory.split('/')# [home aryan desktop python client.txt]
print(f'[D] {directory}')

directory[0] = str('~') # insert user_id
directory[1] = str('1') # insert user_id
directory[2] = str('123123') # insert mac_addr

# directory.insert(3, str('1')) # insert user_id
# directory.insert(4, str('123123')) # insert mac_addr

directory = '/'.join(directory)
directory = os.path.expanduser(directory) 
print(f'[F] {directory}')