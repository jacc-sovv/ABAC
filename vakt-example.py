#pip install vakt
# Implementation that stores Policies in memory. It's not backed by any file, 
# so every restart of your application will swipe out everything that was stored.
# Useful for testing or if we want to do a one-time showcase of ABAC to display 
# that ABAC prevents against a specifically crafted attack

import vakt
from vakt.rules import Eq, Any, StartsWith, And, Greater, Less, EndsWith

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
policies = [policy, policy2]
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