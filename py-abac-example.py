
#pip install py-abac to get started
#From the py-abac docs:
#Currently the In-Memory storage returns all policies for evaluation by PDP. 
#In the future indexing will be added for filtering of policies to improve lookup efficiency.

#It should be noted that the In-Memory backend does not persist policies 
#and thus there is a risk of losing all policies on system restarts.


from py_abac import PDP, Policy, AccessRequest
from py_abac.storage.memory import MemoryStorage

# Policy definition in JSON
policy_json = {
    "uid": "1",
    "description": "Max and Nina are allowed to create, delete, get any "
                   "resources only if the client IP matches.",
    "effect": "allow",
    "rules": {
        "subject": [{"$.name": {"condition": "Equals", "value": "Max"}},
                    {"$.name": {"condition": "Equals", "value": "Nina"}}],
        "resource": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "action": [{"$.method": {"condition": "Equals", "value": "create"}},
                   {"$.method": {"condition": "Equals", "value": "delete"}},
                   {"$.method": {"condition": "Equals", "value": "get"}}],
        "context": {"$.ip": {"condition": "CIDR", "value": "127.0.0.1/32"}}
    },
    "targets": {},
    "priority": 0
}
# Parse JSON and create policy object
policy = Policy.from_json(policy_json)

# Setup policy storage
storage = MemoryStorage()
# Add policy to storage
storage.add(policy)

# Create policy decision point
pdp = PDP(storage)

# A sample access request JSON
request_json = {
    "subject": {
        "id": "", 
        "attributes": {"name": "Max"}
    },
    "resource": {
        "id": "", 
        "attributes": {"name": "myrn:example.com:resource:123"}
    },
    "action": {
        "id": "", 
        "attributes": {"method": "get"}
    },
    "context": {
        "ip": "127.0.0.1"
    }
}
# Parse JSON and create access request object
request = AccessRequest.from_json(request_json)

# Check if access request is allowed. Evaluates to True since 
# Max is allowed to get any resource when client IP matches.

print(f"Is the request allowed? {pdp.is_allowed(request)}")

assert pdp.is_allowed(request)