import os

# directories = []
# files = []

# folder = '/home/osaka/Documents/NEA_v2/NEA/scratch'

# def traverse_preorder(root):
#     stack = [root]  # stack for DFS
#     print(f'stack: {stack}')
    
#     while stack:
#         current = stack.pop()
#         print(f'📂 Traversing: {current}')
#         directories.append(current)

#         try:
#             children = os.listdir(current)
#         except PermissionError:
#             print(f'❌ Permission denied: {current}')
#             continue

#         for item in reversed(children):  # reversed to keep order consistent
#             full_path = os.path.join(current, item)
#             if os.path.isdir(full_path):
#                 stack.append(full_path)
#             else:
#                 print(f'📖 Found file: {full_path}')
#                 files.append(full_path)

# # Start traversal
# traverse_preorder(folder)

# print('\n✅ Traversal Complete')
# print(f'Directories:\n{directories}')
# print(f'Files:\n{files}')


class FolderInitializer:
    def __init__(self, event_id, path, event_type="created", origin="mkdir"):
        self.event_id = event_id
        self.path = path
        self.event_type = event_type
        self.origin = origin

    def preorderTraversal(self):
        stack = [self.path]
        directories = []
        files = []

        while stack:
            current = stack.pop()
            print(f'📂 Traversing: {current}')
            directories.append(current)

            try:
                children = os.listdir(current)
            except PermissionError:
                print(f'❌ Permission denied: {current}')
                continue

            for item in reversed(children):  # reversed to keep order consistent
                full_path = os.path.join(current, item)
                if os.path.isdir(full_path):
                    stack.append(full_path)
                else:
                    print(f'📖 Found file: {full_path}')
                    files.append(full_path)
            
        print('\n✅ Traversal Complete')
        print(f'Directories:\n{directories}')
        print(f'Files:\n{files}')
    
object = FolderInitializer(1, '/home/osaka/Documents/NEA_v2/NEA/scratch/traversal')
object.preorderTraversal()