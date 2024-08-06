
# Overview:

```mini_CAGE``` is simplified version of the CAGE 2 environment with a focus on greater execution speed and the added ability to perform parallelisable runs. 

The package mimics the basic reinforcement learning components of the CAGE 2 environment (e.g. state-action space, reward, etc.), but abstracts the bulky files and complex processes, resulting in a streamlined and more accessible framework that retains core functionalities.

# Usage:

The only package dependency is ```numpy``` and the environment follows the basic OpenAI gym API structure. A simple implementation is given below, in which the two pre-programmed agents (react-restore and meander) compete for 100 timesteps.

```python

from CAGE_2_FIXED.mini_CAGE import (
    SimplifiedCAGE, Meander_minimal, React_restore_minimal)

# instantiate the environment
env = SimplifiedCAGE(num_envs=1)
state, info = env.reset()

# instantiate  the agents 
red_agent = Meander_minimal()
blue_agent = React_restore_minimal() 

for i in range(100):

    # select the agent actions
    blue_action = blue_agent.get_action(
        observation=state['Blue'])
    red_action = red_agent.get_action(
        observation=state['Red']) 

    # update the environment
    state, reward, done, info = env.step(
        blue_action=blue_action, red_action=red_action)
```

# Comparison:

The environment is based off of the most up to date version of [CAGE 2](https://github.com/cage-challenge/CybORG/tree/cage-challenge-2). The introduced modifications are listed as follows:

- **Red Agent Interface** - the environment can now be used to train both red and blue agents, having fixed the problems with the wrapper in original CAGE 2 implementation. 

- **Port and IP Management** - individual hosts no longer contain IP or port information. Machines have pre-specified processeses running, furthermore exploits are mapped to their corresponding decoy processes rather than performing a check for port availability.

- **Wrappers** - the default state is given as a dictionary containing a vector for both the red and blue agent's observations. In this form it should be readily compatible with reinforcement learning agents.

- **Bug fixes** - the environment is kept faithful to the original and therefore includes the bugs present in the previous iteration, allowing for more direct comparison. However, the environment can also be run with the bugs removed. 

## Speed:

The simplification and parallelisation of the CAGE environment signficiantly improves the environment execution speed, resulting in almost 1000x acceleration improvement when run on a single CPU. 

| Number of Episodes | CAGE 2 Time (s) | Mini CAGE Time (s) | Improvement |
| ------------------ | --------------- | ------------------ | ----------- |
| 1                  | 1.16            | 0.12               | ~15x        |
| 10                 | 7.52            | 0.12               | ~65x        |
| 100                | 113.62          | 0.13               | ~950x       |
| 1000               | 998.87          | 1.35               | ~800x       |  


## Performance:

To confirm the equivalence between the mini_CAGE environment and the CAGE 2 environment, reward was compared across 6 combinations of attacker-defender pairs over 500 epsiodes for 100 timesteps each. +/- indicates the standard error.

| Attacker | Defender      | CAGE 2 Score | Mini CAGE Score |
| -------- | ------------- | ------------ | --------------- |
| B-Line   | React-Restore | -159 +/- 2   | -156 +/ 2       |
| B-Line   | React-Decoy   | -69 +/- 2    | -68 +/- 2       |
| B-Line   | Sleep         | -1141 +/- 1  | -1141 +/- 1     |
| Meander  | React-Restore | -69 +/- 2    | -68 +/- 2       |  
| Meander  | React-Decoy   | -61 +/- 1    | -63 +/- 1       |
| Meander  | Sleep         | -1067 +/- 2  | -1067 +/- 1     |





