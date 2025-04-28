import os

formatted_path = "/home/yangchen/NEA/scratch/21/12/21.py"
folder_path = "/home/yangchen/NEA/scratch"

src_path = os.path.relpath(formatted_path, folder_path)

print(src_path)

