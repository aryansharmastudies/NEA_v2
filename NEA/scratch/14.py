invites = {'folders': {'anjali': {'167132875827157': [['COMEON', 'GIc07V9FAa', 'aryan'], ['aye', 'EZGCUVpVys', 'aryan'], ['feetpics', '1YYygSKiLc', 'aryan'], ['sigma', 'iYsfe5z4zh', 'aryan'], ['2025', 'UhjDUQsQG5', 'aryan']]}, 'shravan': {'167132875827157': [['aye', 'EZGCUVpVys', 'aryan'], ['feetpics', '1YYygSKiLc', 'aryan']]}}, 'groups': {}}
user = 'anjali'
mac_addr = '167132875827157'

alerts = []

if user in invites['folders']:
    if mac_addr in invites['folders'][user]:
        for invite in invites['folders'][user][mac_addr]:
            alerts.append(invite)

print(alerts)