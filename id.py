import subprocess
import os
import uuid

def get_id():
    if 'nt' in os.name:
        #print("Hey)")
        id = str(subprocess.check_output('wmic csproduct get uuid')).split('\\r\\n')[1].strip('\\r').strip()
        #print((id))
        id = id[-12:]
        return id
    else:
        id = str(subprocess.check_output(['cat', '/etc/machine-id']), 'utf-8')
        #print(id)
        return id

get_id()