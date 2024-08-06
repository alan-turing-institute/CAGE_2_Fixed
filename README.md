## CAGE 2 Challenge Environment - Alternate versions

This repository contains:

- A debugged version of the CAGE 2 CybORG environment that is compatible with the CAGE 2 challenge
  - [Debugged Version of CAGE 2 CybORG](CAGE_2_Fixed/Debugged_CybORG)
- A simple and fast reimplementation of the CAGE 2 CybORG environment
  - [Mini CAGE 2 Reimplementation](CAGE_2_Fixed/mini_CAGE)
- Additional information on how the environment works and things we’ve learnt that may be helpful for future users

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