from scapy.layers.dot11 import Dot11Elt
from Sniffer_dir.sniff import *


class WIFIScanner:
    networks = {}
    devices = []

    def __init__(self, sniffer: Sniffer):
        self.sniffer = sniffer

    def __init__(self, sniffer: Sniffer, target_BSSID: str = ""):
        self.sniffer = sniffer
        self.target_BSSID = target_BSSID

    def Scannerfunc(self, pkt):
        if pkt.haslayer('Dot11Beacon') or pkt.haslayer('Dot11ProbeResp'):
            if pkt.haslayer("Dot11EltDSSSet"):
                channel, SSID = pkt["Dot11EltDSSSet"].channel, pkt.info.decode("utf-8")
                if str(SSID) == "":
                    SSID = "(Hidden Network)"
                BSSID = pkt["Dot11FCS"].addr2
                pwr = pkt["RadioTap"].dBm_AntSignal

                standart = self.__recognize_802_11_standart(pkt, str(pkt["RadioTap"].ChannelFrequency)[0])

                self.networks[str(channel) + str(SSID) + str(BSSID)] = {
                    "SSID":     str(SSID),
                    "channel":  str(channel),
                    "BSSID":    str(BSSID),
                    "PWR":      str(pwr),
                    "Standart": str(standart)
                }

    def ScannerDevicesfunc(self, pkt):
        if pkt.haslayer("Dot11FCS"):
            if pkt["Dot11FCS"].addr1 == self.target_BSSID or pkt["Dot11FCS"].addr2 == self.target_BSSID or \
                    pkt["Dot11FCS"].addr3 == self.target_BSSID:
                if pkt["Dot11FCS"].addr1 != self.target_BSSID and pkt["Dot11FCS"].addr1 is not None:
                    if (str(pkt["Dot11FCS"].addr1).lower().find("01:00:5e") != 0) and (  # check if addr is broadcast
                            str(pkt["Dot11FCS"].addr1).lower().find("33:33:") != 0) and (
                            str(pkt["Dot11FCS"].addr1).lower() != "ff:ff:ff:ff:ff:ff"):
                        if pkt["Dot11FCS"].addr1 not in self.devices:
                            self.devices.append(str(pkt["Dot11FCS"].addr1))
                if pkt["Dot11FCS"].addr2 != self.target_BSSID and pkt["Dot11FCS"].addr2 is not None:
                    if (str(pkt["Dot11FCS"].addr2).lower().find("01:00:5e") != 0) and (
                            str(pkt["Dot11FCS"].addr2).lower().find("33:33:") != 0) and (
                            str(pkt["Dot11FCS"].addr2).lower() != "ff:ff:ff:ff:ff:ff"):
                        if pkt["Dot11FCS"].addr2 not in self.devices:
                            self.devices.append(str(pkt["Dot11FCS"].addr2))
                if pkt["Dot11FCS"].addr3 != self.target_BSSID and pkt["Dot11FCS"].addr3 is not None:
                    if (str(pkt["Dot11FCS"].addr3).lower().find("01:00:5e") != 0) and (
                            str(pkt["Dot11FCS"].addr3).lower().find("33:33:") != 0) and (
                            str(pkt["Dot11FCS"].addr3).lower() != "ff:ff:ff:ff:ff:ff"):
                        if pkt["Dot11FCS"].addr3 not in self.devices:
                            self.devices.append(str(pkt["Dot11FCS"].addr3))

    def __recognize_802_11_standart(self, pkt, Freq):
        standart = ""
        if Freq == "2":
            standart = "b"
        elif Freq == "5":
            standart = "a"
        elif Freq == "6":
            standart = "ax"
        try:
            dot11elt = pkt.getlayer(Dot11Elt)
            while dot11elt:
                if int(dot11elt.ID) == 45 and (Freq == "2" or Freq == "5"):  # HT
                    standart = "n"
                if int(dot11elt.ID) == 191 and Freq == "5":  # VHT
                    standart = "ac"
                if int(dot11elt.ID) == 35 and Freq == "6":  # HE
                    standart = "ax"
                dot11elt = dot11elt.payload.getlayer(Dot11Elt)
        except IndexError:
            pass
        return standart

    def GetNetworksInfo(self):
        return self.networks

    def GetDevicesInfo(self):
        return self.devices

    def scan(self, **kwargs):  # доп аргументы исключительно для таймаута и прочих дополнений на усмотрение
        self.sniffer.exec(prn=self.Scannerfunc, **kwargs)

    def scan_devices(self, **kwargs):  # доп аргументы исключительно для таймаута и прочих дополнений на усмотрение
        self.sniffer.exec(prn=self.ScannerDevicesfunc, **kwargs)
