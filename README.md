## PRINCE under Differential Fault Attack: Now in 3D

****

This repository contains the implementation of 3 fault attack models on PRINCE and PRINCEv2. The attack models are listed below:
1. Integral Fault Attack
2. Slow Diffusion Fault Attack
3. Random Bit Fault Attack

The implementation also contains the code for injecting the faults at the reflection point.

****

To run the code, the following commands need to be run:
1. `export LD_LIBRARY_PATH=.`
2. `python3 main.py -a <ATTACK_TYPE> -v <PRINCE_VERSION> [-r]`

* -a:	
	1. Integral Fault Attack
	2. Slow Diffusion Fault Attack
	3. Random Bit Fault Attack

* -v:	
	1. PRINCE
	2. PRINCEv2

* -r:	If reflection needed (Optional Argument)
