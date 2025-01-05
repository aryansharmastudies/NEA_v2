import os
def l_wlan_ip():
    try:
        gw = os.popen('ip -4 route show default').read().split()
    except: 
        return
    return gw[-3]
