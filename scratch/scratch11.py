import os
src_path = 'C:\\Users\\osaka\\Documents\\Github\\git.gay'
src_path = os.path.normpath(src_path).replace('\\', '/')
src_path = src_path.split('/')
src_path = src_path[3:]

x = 'alpha'
y = 'beta'
z = '~'
src_path.insert(0, x)
src_path.insert(0, y)
src_path.insert(0, z)
print(src_path)

src_path = '/'.join(src_path)  # returns # TODO figure out the final path
src_path = os.path.expanduser(src_path)  # expands ~ to /home/user

print(src_path)