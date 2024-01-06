from Sniffer_dir.sniff import *

class WIFIScanner:
	
	networks = {}
	devices = []

	def __init__(self, sniffer: Sniffer):
		self.sniffer = sniffer

	def __init__(self, sniffer:Sniffer, target_BSSID: str):
		self.sniffer = sniffer
		self.target_BSSID = target_BSSID

	def Scannerfunc(self, pkt):
		if pkt.haslayer('Dot11Beacon') or pkt.haslayer('Dot11ProbeResp'):
			if pkt.haslayer("Dot11EltDSSSet"):
				channel, SSID = pkt["Dot11EltDSSSet"].channel, pkt.info.decode("utf-8")
				BSSID = pkt["Dot11FCS"].addr2
				self.networks[str(channel)+str(SSID)+str(BSSID)] = {
					"SSID": str(SSID),
					"channel": str(channel),
					"BSSID": str(BSSID)
				}
	def ScannerDevicesfunc(self, pkt):
		if pkt.haslayer("Dot11FCS"):
			if pkt["Dot11FCS"].addr1 == self.target_BSSID or pkt["Dot11FCS"].addr2 == self.target_BSSID or \
					pkt["Dot11FCS"].addr3 == self.target_BSSID:
				if pkt["Dot11FCS"].addr1 != self.target_BSSID:
					if ( str(pkt["Dot11FCS"].addr1).lower().find("01:00:5e") != 0 ) and (  # check if addr is broadcast
							str(pkt["Dot11FCS"].addr1).lower().find("33:33:") != 0 ) and (
							str(pkt["Dot11FCS"].addr1).lower() != "ff:ff:ff:ff:ff:ff"):
						if pkt["Dot11FCS"].addr1 not in self.devices:
							self.devices.append(str(pkt["Dot11FCS"].addr1))
				if pkt["Dot11FCS"].addr2 != self.target_BSSID:
					if (str(pkt["Dot11FCS"].addr1).lower().find("01:00:5e") != 0) and (
							str(pkt["Dot11FCS"].addr1).lower().find("33:33:") != 0) and (
							str(pkt["Dot11FCS"].addr1).lower() != "ff:ff:ff:ff:ff:ff"):
						if pkt["Dot11FCS"].addr2 not in self.devices:
							self.devices.append(str(pkt["Dot11FCS"].addr2))
				if pkt["Dot11FCS"].addr3 != self.target_BSSID:
					if (str(pkt["Dot11FCS"].addr1).lower().find("01:00:5e") != 0) and (
							str(pkt["Dot11FCS"].addr1).lower().find("33:33:") != 0) and (
							str(pkt["Dot11FCS"].addr1).lower() != "ff:ff:ff:ff:ff:ff"):
						if pkt["Dot11FCS"].addr3 not in self.devices:
							self.devices.append(str(pkt["Dot11FCS"].addr3))

	def GetNetworksInfo(self):
		return self.networks

	def GetDevicesInfo(self):
		return self.devices

	def scan(self, **kwargs): # доп аргументы исключительно для таймаута и прочих дополнений на усмотрение
		self.sniffer.exec(prn=self.Scannerfunc, **kwargs)

	def scan_devices(self, **kwargs): # доп аргументы исключительно для таймаута и прочих дополнений на усмотрение
		self.sniffer.exec(prn=self.ScannerDevicesfunc, **kwargs)
				
