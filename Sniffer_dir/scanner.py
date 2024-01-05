from Sniffer_dir.sniff import *

class WIFIScanner:
	
	networks = {}

	def __init__(self, sniffer:Sniffer):
		self.sniffer = sniffer

	def Scannerfunc(self, pkt):
		if pkt.haslayer('Dot11Beacon') or pkt.haslayer('Dot11ProbeResp'):
			if pkt.haslayer("Dot11EltDSSSet"):
				channel, SSID = pkt["Dot11EltDSSSet"].channel, pkt.info.decode("utf-8")
				BSSID = pkt["Dot11FCS"].addr2
				self.networks[str(channel)+str(SSID)+str(BSSID)] = {
					"SSID": str(SSID),
					"channel": str(channel),
					"BSSID" : str(BSSID)
				}

	def GetNetworksInfo(self):
		return self.networks

	def scan(self, **kwargs): # доп аргументы исключительно для таймаута и прочих дополнений на усмотрение
		self.sniffer.exec(prn=self.Scannerfunc, **kwargs)
				
