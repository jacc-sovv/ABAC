#pip install vakt
#Implementation that stores Policies in memory. It's not backed by any file 
# or something, so every restart of your application will swipe out everything that was stored.
# Useful for testing, and if we want to do a one-time showcase of ABAC
import vakt
from vakt.rules import Eq, Any, StartsWith, And, Greater, Less

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
storage = vakt.MemoryStorage()
storage.add(policy)
guard = vakt.Guard(storage, vakt.RulesChecker())

inq = vakt.Inquiry(action='fork',
                   resource='repos/google/tensorflow',
                   subject={'name': 'larry', 'stars': 80},
                   context={'referer': 'https://github.com'})

assert guard.is_allowed(inq)