shared_Users = ['admin:x230', 'admin:admins_MBP', 'joel:joels_pixel']

for user_device in shared_Users:
    user = user_device.split(':')[0]
    device = user_device.split(':')[1]
    
    
    
    print(user, device)