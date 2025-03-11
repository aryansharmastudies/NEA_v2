import os
def l_wlan_ip():
    gw = os.popen('ip -4 route show default').read().split()
    print((gw)[-3])
    return gw[-3]
