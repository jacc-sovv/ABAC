#pip install vakt
# Implementation that stores Policies in memory. It's not backed by any file, 
# so every restart of your application will swipe out everything that was stored.
# Useful for testing or if we want to do a one-time showcase of ABAC to display 
# that ABAC prevents against a specifically crafted attack

import vakt
from vakt.rules import Eq, Any, StartsWith, And, Greater, GreaterOrEqual, Less, LessOrEqual, EndsWith, In, NotIn, CIDR

policy = vakt.Policy(
    123456,
    actions=[Eq('fork'), Eq('clone')],
    resources=[StartsWith('repos/Google', ci=True)],
    subjects=[{'name': Any(), 'stars': And(Greater(50), Less(999))}],
    effect=vakt.ALLOW_ACCESS,
    context={'referer': Eq('https://github.com')},
    description="""
    Allow to fork or clone any Google repository for
    users that have > 50 and < 999 stars and came from Github
    """
)

policy2 = vakt.Policy(
    1,
    actions=[Eq('get')],
    resources=[EndsWith('.log')],
    subjects=[{'role': 'admin'}],
    effect=vakt.ALLOW_ACCESS,
    description="""
    Allow admins to get the log files
    """
)

#Example policy on a PLC resource using certain deviceIDs and example CIDR's
policy3 = vakt.Policy(
    2,
    actions=[Eq('get'), Eq('set')],
    subjects=[{'name': Any(), 'device_id' : In('111.222', '111.333', '111.444'), 
                'ip' : CIDR('192.168.2.0/24')}],
    resources=[Eq('PLC')],
    effect=vakt.ALLOW_ACCESS
)

# Example policy on a PLC during a certain time 08:00 to 17:00 i.e. 8am to 5pm as an engineer
policy4 = vakt.Policy(
    3,
    actions=[Eq('get'), Eq('set')],
    subjects=[{'name': Any(), 'role' : Eq('engineer')}],         
    resources=[Eq('PLC')],
    context={'time' : And(GreaterOrEqual(8.00), LessOrEqual(17.00))},
    effect=vakt.ALLOW_ACCESS,
    description="""
    Allow engineers to access PLC during work hours 8am - 5pm
    """
)

# Example policy on a PLC at a certain status as an engineer
policy5 = vakt.Policy(
    4,
    actions=[Eq('get'), Eq('set')],
    subjects=[{'name': Any(), 'role' : Eq('engineer')}],         
    resources=[Eq('PLC')],
    context={'status' : NotIn('Stopped')},
    effect=vakt.ALLOW_ACCESS,
    description="""
    Allow engineers to access PLC when it's not stopped
    """
)

policies = [policy, policy2, policy3, policy4, policy5]
storage = vakt.MemoryStorage()
for p in policies:
    storage.add(p)
guard = vakt.Guard(storage, vakt.RulesChecker())

inq = vakt.Inquiry(action='fork',
                   resource='repos/google/tensorflow',
                   subject={'name': 'larry', 'stars': 80},
                   context={'referer': 'https://github.com'})

print(f"Is the first request allowed? {guard.is_allowed(inq)}")

assert guard.is_allowed(inq)

inq2 = vakt.Inquiry(action='get',
                    resource='system.log',
                    subject={'name': 'jack', 'role': 'user'})

print(f"Is the requets by Jack allowed? {guard.is_allowed(inq2)}")

#Test action on a PLC resource with given device_id and ip
abac_inq1 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'jack', 'role' : 'engineer', 'device_id' : '111.222', 
                        'ip' : '192.168.2.4'})

#What happens if we don't have a correct deviceID but are on the same network?
abac_inq2 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'eve', 'role' : 'engineer', 'device_id' : '111.999', 
                        'ip' : '192.168.2.4'})

#What happens if we don't have a correct IP but are on a engineering workstation?
abac_inq3 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'alice', 'role' : 'engineer', 'device_id' : '111.222', 
                        'ip' : '192.250.48.6'})

# Correct role but wrong time
abac_inq4 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'yanye', 'role' : 'engineer'},
                         context={'time' : 18.00})

# Correct role PLC status is Running
abac_inq5 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'yanye', 'role' : 'engineer'},
                         context={'status' : 'Running'})

# Correct role PLC status is Stopped
abac_inq6 = vakt.Inquiry(action='get',
                         resource='PLC',
                         subject={'name' : 'yanye', 'role' : 'engineer'},
                         context={'status' : 'Stopped'})
                        
                        
print(f"Is the ABAC request by Jack allowed? (Workstation on valid network) {guard.is_allowed(abac_inq1)}")
print(f"Is the ABAC request by eve allowed? (Wrong device ID, correct IP) {guard.is_allowed(abac_inq2)}")
print(f"Is the ABAC request by alice allowed? (Correct deviceID, wrong IP) {guard.is_allowed(abac_inq3)}")

print("===============================")
print(f"Is the ABAC request by yanye allowed? (Correct role but wrong time) expected False --> {guard.is_allowed(abac_inq4)}")
print(f"Is the ABAC request by yanye allowed? (Correct role, correct status) expected True --> {guard.is_allowed(abac_inq5)}")
print(f"Is the ABAC request by yanye allowed? (Correct role but wrong status) expected False --> {guard.is_allowed(abac_inq6)}")
