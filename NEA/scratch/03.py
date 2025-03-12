data = {'data':{'devices':[[1,'x230'],[1,'boox'],[2,'chromebook'],[2,'pixel'],[3,'admin_pc']], 'users':[[1,'aryan'],[2,'joel'],[3,'admin']]}}
devices = data['data']['devices']
users = data['data']['users']

id_to_users = {}
users_and_device = {}
for user in users:
    id_to_users[user[0]] = user[1]
    users_and_device[user[1]] = []

for device in devices:
    username = id_to_users[device[0]]
    users_and_device[username].append(device[1])
