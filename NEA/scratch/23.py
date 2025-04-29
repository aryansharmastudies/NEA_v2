import os

x = '/home/bruh/docs/file.txt'
y = '/home/bruh/'
print(os.path.relpath(x, y))