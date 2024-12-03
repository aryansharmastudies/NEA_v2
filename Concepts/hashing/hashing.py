import hashlib
import os
# Execute 'ls' command to list files in the current directory

def ls():
    return os.system('ls')

files = ls()
print(files)

# md5 = hashlib.md5()
# fp = open("stackoverflow.py", "rb")
# for line in fp:
#     print(line)
#     md5.update(line)

# print(md5.hexdigest())
