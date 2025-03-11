import os
directory = r'C:\Users\aryan\gaming\valorant'

# directory = directory.split('\\')
# directory = '~\\' + os.path.join(*directory[2:])
directory = directory.split('\\')
directory = directory[3:]
directory = '~\\' + '\\'.join(directory)

print(directory)