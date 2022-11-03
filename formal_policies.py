# Application of ABAC for PLC: Policy Formalization

import vakt
from vakt.rules import Eq, Any, StartsWith, And, Greater, GreaterOrEqual, Less, LessOrEqual, EndsWith, In, NotIn, CIDR

# List of Policies ===============================
communication_setup = vakt.Policy(
    1,
    actions=[Eq('CommSetup')],
    subjects=[{'User.AccessLevel' : In('Operator', 'Engineer', 'Administrator'),
               'User.Device' : Eq("Equip21LOrgABC")}],
    context={'Env.AccessTime' : And(GreaterOrEqual(7.00), LessOrEqual(16.00)),
             'Env.AccessLoc' : Eq("OrgABC.local"),
             'PLC.OperatingMode' : Eq('Remote')},
    resources=[Eq('PLC')],
    effect=vakt.ALLOW_ACCESS
)

memory_write = vakt.Policy(
    2,
    actions=[Eq('WriteMem')],
    subjects=[{'User.AccessLevel' : In('Engineer', 'Administrator')}],
    context={'PLC.OperatingMode' : Eq('Program'),
             'PLC.Status' : Eq('Stop')},
    resources=[Eq('PLC')],
    effect=vakt.ALLOW_ACCESS
)

firmware_update = vakt.Policy(
    3,
    actions=[Eq('Update')],
    subjects=[{'User.AccessLevel' : Eq('Administrator')}],
    context={'PLC.OperatingMode' : Eq('Program'),
             'PLC.Status' : Eq('Stop')},
    resources=[Eq('PLC')],
    effect=vakt.ALLOW_ACCESS
)

# Setup ===============================
policies = [communication_setup, memory_write, firmware_update]

storage = vakt.MemoryStorage()
for p in policies:
    storage.add(p)
guard = vakt.Guard(storage, vakt.RulesChecker())

# Communication Setup Test Inquries ===============================
print("Testing Communication Setup Inquries")

comm_inquiry_1 = vakt.Inquiry(action='CommSetup',
                         subject={'User.AccessLevel' : 'Engineer',
                                  'User.Device' : 'Equip21LOrgABC'},
                         context={'Env.AccessTime' : 10.00,
                                  'Env.AccessLoc' : 'OrgABC.local',
                                  'PLC.OperatingMode' : 'Remote'},
                         resource='PLC')

comm_inquiry_2 = vakt.Inquiry(action='CommSetup',
                         subject={'User.AccessLevel' : 'User',
                                  'User.Device' : 'Equip21LOrgABC'},
                         context={'Env.AccessTime' : 10.00,
                                  'Env.AccessLoc' : 'OrgABC.local',
                                  'PLC.OperatingMode' : 'Remote'},
                         resource='PLC')

comm_inquiry_3 = vakt.Inquiry(action='CommSetup',
                         subject={'User.AccessLevel' : 'Operator',
                                  'User.Device' : 'Equip21LOrgABC'},
                         context={'Env.AccessTime' : 20.00,
                                  'Env.AccessLoc' : 'OrgABC.local',
                                  'PLC.OperatingMode' : 'Remote'},
                         resource='PLC')

comm_inquiry_4 = vakt.Inquiry(action='CommSetup',
                         subject={'User.AccessLevel' : 'Operator',
                                  'User.Device' : 'Equip21LOrgABC'},
                         context={'Env.AccessTime' : 5.00,
                                  'Env.AccessLoc' : 'OrgABC.local',
                                  'PLC.OperatingMode' : 'Remote'},
                         resource='PLC')

print(f"\tAll Correct - Expected True --> {guard.is_allowed(comm_inquiry_1)}")
print(f"\tIncorrect User.AccessLevel - Expected False --> {guard.is_allowed(comm_inquiry_2)}")
print(f"\tIncorrect Env.AccessTime (too late) - Expected False --> {guard.is_allowed(comm_inquiry_3)}")
print(f"\tIncorrect Env.AccessTime (too early) - Expected False --> {guard.is_allowed(comm_inquiry_4)}")

# Memory Write Test Inquries ===============================
print("\nTesting Memory Write Inquries")

mem_inquiry_1 = vakt.Inquiry(action='WriteMem',
                         subject={'User.AccessLevel' : 'Administrator'},
                         context={'PLC.OperatingMode' : 'Program',
                                  'PLC.Status' : 'Stop'},
                         resource='PLC')

mem_inquiry_2 = vakt.Inquiry(action='WriteMem',
                         subject={'User.AccessLevel' : 'Administrator'},
                         context={'PLC.OperatingMode' : 'Program',
                                  'PLC.Status' : 'Running'},
                         resource='PLC')

mem_inquiry_3 = vakt.Inquiry(action='CommSetup',
                         subject={'User.AccessLevel' : 'Administrator'},
                         context={'PLC.OperatingMode' : 'Program',
                                  'PLC.Status' : 'Running'},
                         resource='PLC')

print(f"\tAll Correct - Expected True --> {guard.is_allowed(mem_inquiry_1)}")
print(f"\tIncorrect PLC.Status - Expected False --> {guard.is_allowed(mem_inquiry_2)}")
print(f"\tIncorrect action - Expected False --> {guard.is_allowed(mem_inquiry_3)}")

# Firmware Update Test Inquries ===============================
print("\nTesting Firmware Update Inquries")

update_inquiry_1 = vakt.Inquiry(action='Update',
                         subject={'User.AccessLevel' : 'Administrator'},
                         context={'PLC.OperatingMode' : 'Program',
                                  'PLC.Status' : 'Stop'},
                         resource='PLC')

update_inquiry_2 = vakt.Inquiry(action='Update',
                         subject={'User.AccessLevel' : 'Engineer'},
                         context={'PLC.OperatingMode' : 'Program',
                                  'PLC.Status' : 'Stop'},
                         resource='PLC')

print(f"\tAll Correct - Expected True --> {guard.is_allowed(update_inquiry_1)}")
print(f"\tIncorrect User.AccessLevel - Expected False --> {guard.is_allowed(update_inquiry_2)}")
