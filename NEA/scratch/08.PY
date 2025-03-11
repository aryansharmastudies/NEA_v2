ip_map = {"users":{}}
def track_ip(user, mac_addr, ip):
    if user not in ip_map["users"]:
        ip_map["users"][user] = {}

    ip_map["users"][user][mac_addr] = ip
track_ip("aryan", '123123123', 'qwerty')
print(ip_map)