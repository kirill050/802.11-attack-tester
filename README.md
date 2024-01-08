<h1 align=center>802.11 attack tester</h1>

The 802.11 attack tester is a multifunctional console application designed 
to test the effectiveness of the WIDS/WIPS (wireless intrusion detection/prevention system)
in 802.11 networks.

The application provides an opportunity for the operator to simulate the execution 
of the most common attacks on 802.11 networks in order to assess the quality 
of countering an attack based on the success of the attack output by the application.

## Installing

Install with `pip3` or your favorite PyPI package manager.

```sh
./setup.sh
```

## Launching

To launch just run:
```sh
python3 main.py <int1> <int2>
````
Replace `int1` by the name of your wireless interface that will be used for attacking imitation proposes,
and `int2` by the name of your wireless interface that will be used for quality analyzing (sniffing) proposes.

Example:
```sh
python3 main.py wlan0 wlan1mon
````

<b><i>Both `int1` and `int2` should be able to be switched to monitor mode!!!</b></i>

To identify the names of interfaces run:
```sh
iwconfig
````

<h2 align=center>Using 802.11 attack tester</h2>

To select an attack: enter the number of this attack in the main window of the program after launch. Ex:
![Attack_choice](imgs%2Fmain_window.png)

After selecting the attack, 
it is necessary to determine the frequency range in which the attack will be carried out. 
To do this, enter the number of the frequency range (or a combination of them) from the corresponding table 
(currently only the 2.4GHz band is supported). Ex:
![Band_choice](imgs%2Fband_choice.png)

Then the selected frequency range(s) will be scanned to find the wireless access points (AP) working on them.
![Band_scanning](imgs%2Fband_scanning.png)

## RTS Flood Attack

After scanning of the chosen frequency range(s), you should choose net to be attacked. Ex:
![RTS_net_choice](imgs%2Frts_net_choice.png)

Then attack will be started with demonstration of it`s efficiency by bar plot showing
percentage of malicious and normal frames at this net.
![RTS_attack](imgs%2Frts_attack.png)

To stop the attack and return to the main window press `q` button.

## Null Probe Response Attack

After scanning of the chosen frequency range(s), 
you should choose net(s) in which the search for devices to attack them will be performed. Ex:
![NPR_nets](imgs%2Fnpr_nets.png)

Then chosen nets will be scanned:
![NPR_nets_scan](imgs%2Fnpr_nets_scan.png)

To determine target devices for this attack write their numbers separated by commas. Ex:
![NPR_devices](imgs%2Fnpr_devices.png)

Then attack will be started with demonstration of it`s efficiency by plot showing
number of frames received/sent by attacking device per the technological cycle of management (one clock cycle).
![NPR_attack](imgs%2Fnpr_attack.png)

To stop the attack and return to the main window press `q` button.

## Rogue Twin Attack
After scanning of the chosen frequency range(s), you should choose net to be attacked. Ex:
![RogueTwin_net_choice](imgs%2Frogue_twin_net.png)


Then attack will be started with demonstration of it`s efficiency by bar plot showing
percentage of frames at real and fake net.
![RogueTwin_attack](imgs%2Frogue_twin_attack.png)

To stop the attack and return to the main window press `q` button.

## Deauthentication Attack

After scanning of the chosen frequency range(s), 
you should choose net(s) in which the search for devices to attack them will be performed. Ex:
![Deauth_nets](imgs%2Fdeauth_nets.png)

Then chosen nets will be scanned:
![Deauth_nets_scan](imgs%2Fdeauth_nets_scan.png)

To determine target devices for this attack write their numbers separated by commas. Ex:
![Deauth_devices](imgs%2Fdeauth_devices.png)

Then attack will be started with demonstration of it`s efficiency by plot showing
number of frames received/sent by attacking device per the technological cycle of management (one clock cycle).
![Deauth_attack](imgs%2Fdeauth_attack.png)

To stop the attack and return to the main window press `q` button.

## Disassociation Attack

After scanning of the chosen frequency range(s), 
you should choose net(s) in which the search for devices to attack them will be performed. Ex:
![Disass_nets](imgs%2Fdissas_nets.png)

Then chosen nets will be scanned:
![Disass_nets_scan](imgs%2Fdissas_nets_scan.png)

To determine target devices for this attack write their numbers separated by commas. Ex:
![Disass_devices](imgs%2Fdissas_devices.png)

Then attack will be started with demonstration of it`s efficiency by plot showing
number of frames received/sent by attacking device per the technological cycle of management (one clock cycle).
![Disass_attack](imgs%2Fdissas_attack.png)

To stop the attack and return to the main window press `q` button.

## Omerta Attack

After scanning of the chosen frequency range(s), 
you should choose net(s) to be attacked. Ex:
![Omerta_nets](imgs%2Fomerta_nets.png)

Then chosen nets will be scanned:
![Omerta_nets_scan](imgs%2Fomerta_nets_scan.png)

Then attack will be started with demonstration of it`s efficiency by plot showing
number of frames received/sent by attacking net per the technological cycle of management (one clock cycle).
![Omerta_attack](imgs%2Fomerta_attack.png)

To stop the attack and return to the main window press `q` button.
