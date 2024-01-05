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

<b><i>Both `int1` and `int2` should be able to be switched to monitor mode!!!</b></i>

To identify the names of interfaces run:
```sh
iwconfig
````
