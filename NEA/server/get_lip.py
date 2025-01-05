import os
def l_wlan_ip():
    gw = os.popen('ip -4 route show default').read().split()
    return gw[-3]
