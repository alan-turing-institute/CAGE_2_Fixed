# CAGE 2 Challenge Environment - Alternate versions

This repository contains:

- A debugged version of the CAGE 2 CybORG environment that is compatible with the CAGE 2 challenge
  - [Debugged Version of CAGE 2 CybORG](./Debugged_CybORG)
- A simple and fast reimplementation of the CAGE 2 CybORG environment
  - [Mini CAGE 2 Reimplementation](./mini_CAGE)
- Additional information on how the environment works and things we’ve learnt that may be helpful for future users

# Extended CAGE 2 Developer Guide

This guide extends the previous CAGE 2 developer guide, highlighting features of the environment that are useful for successful model implementation. 

## Network Diagram


## Action Space

The blue agent can take one of several actions in each timestep: 
- analyse a host - reveals with 100% certainty the presence of an exploited host
- remove host - remove low level access users from a host
- restore host - remove privliged users from a host
- place a decoy - set-up a decoy service on a host. If selected the attacker's action will fail.


One of the unique features of the CAGE 2 environment is that both agents take actions simultaneously, rather than sequentially. This means that to some degree an agent must attempt to anticipate the actions of its opponent, especially as some actions will have a nullifying effect if they occur at the same time. Below is a list of action priorities should they occur simultaneously:

| Red Agent Action | Blue Agent Action | Priority |
|------------------|-------------------|----------|
| Escalate         | Remove            | Escalate |
| Exploit          | Decoy             | Exploit  |
| Exploit          | Restore           | Exploit  |

## Observation Space

The blue agent observation space is processed using the Wrappers available in [Wrappers](./Debugged_CybORG/CybORG/CybORG/Agents/Wrappers/) and the default wrapper is displayed in ChallengeWrapper.py. The blue agent observation has 52 features, with each four consecutive features corresponding to a single node in the network for a total of 13 nodes (in order: Def, Ent0, Ent1, Ent2, OpHost0, OpHost1, OpHost2, Opserver, User0, User1, User2, User3, User4). Each four feature can be one of five combinations describing the node's state:
- [0, 0, 0, 0] = No activity detected on host
- [1, 0, 0, 0] = Scan detected on host
- [1, 0, 1, 1] = Exploit detected in previous turn
- [0, 0, 1, 1] = Exploit detected in prior turns
- [0, 0, 1, 0] = Remove action applied to host (does not indicate successful removal) 

Scans and removal actions have 100% chance of being observed in the state, however for exploitation the probability is less clear. Exploitation actions have a 95% chance of being observed with a few exceptions (details for this can be found in [ExploitAction.py](./Debugged_CybORG/CybORG/CybORG/Shared/Actions/ConcreteActions/ExploitAction.py). SSHBruteForce always has a 100% chance of being observed, consequently an exploit on the OpServer, which can only be exploited using this method, will always be represented in the state. 

## Reward Signal

Reward is assigned based on three conditions: exploiting hosts, restoring hosts and impacting critical hosts. Each host is assigned a numeric value corresponding to its importance (ConfidentialityValue in [Scenario2.yaml](/home/harry/Documents/cyber/BlueTeam/CybORG/CybORG/Shared/Scenarios/Scenario2.yaml)). When a host is exploited this specifies the amount of reward provided: -0.1 for UserHosts and OpHosts, -1 for EntHosts and the OpServer. Using the restore action gives a reward of -1 regardless of which host it is applied to. The only host in which the impact action yields any reward is the OpServer. Allowing this host to be impacted results in a reward of -10. This reward persists until the operational server has been restored and need not be applied in every timestep as the logic of the pre-programmed agents may suggest. The total reward for each timestep is then the sum of exploited host rewards, hosts restored in that timestep and hosts currently being impacted. 


## Appendix



### Additional Information about CAGE 2 Challenge Environment

*** Look at Developer_guide file to see if more issue arise from reading.

- True network diagram
    - Bline agent trajectory
    - Meander agent trajectory
- Actions:
    - Method of taking actions (simultaneous)
        - hierarchy of priority for mutually exclusive actions
    - Talk about Remove (ref issue in my directory)
        - what makes remove work
    - Placing a decoy - ref decoy mapping table
- Observation
    - Vector obs space explanation - what do the bits mean?
    - <95% visibility for blue agent usually
    - All impacts and exploits are visible on the Obs server
    - 100% of brute force exploits are visible
- Rewards
    - Confirm when you get the -10 reward
    - How rewards accumulate

- Appendix
    - Decoy mapping table - hosts
    - Exploits to decoy table
    - Default process and ports
    - Usernames and Password