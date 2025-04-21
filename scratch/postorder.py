# def postOrderTraversal(node):
#     if node is None:
#         return
#     postOrderTraversal(node.left)
#     postOrderTraversal(node.right)
#     print(node.data, end=", ")


import os
formatted_path = '/home/osaka/Documents/NEA_v2/NEA/client'
for root, dirs, files in os.walk(formatted_path, topdown=False):
    print(f"Root: {root}")
    for name in files:
        print(f"File: {name}")
    for name in dirs:
        print(f"Dir: {name}")
    print()

    