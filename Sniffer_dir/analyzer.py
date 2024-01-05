from scapy.all import * 
import queue
from time import sleep
import plotext as plt
import Drawer

class RTS_Analyzer:
	packets = 1
	rts_packets = 1 
	mutex = threading.Lock()

	def __init__(self, timeout=5):
		self.timeout = timeout  # в секундах
		return

	def Analyzer(self, q: queue.Queue, attacking_addr, target_addr):
		while True:
			packet = q.get()
			self.mutex.acquire()
			if packet.haslayer("Dot11FCS"):
				if packet["Dot11FCS"].type == 1 and packet["Dot11FCS"].subtype == 0xb:
					if packet["Dot11FCS"].addr1 == target_addr and packet["Dot11FCS"].addr2 == attacking_addr:
						self.rts_packets += 1
			try:
				if packet["Dot11FCS"].addr1 == target_addr or packet["Dot11FCS"].addr2 == target_addr or packet["Dot11FCS"].addr3 == target_addr:
					self.packets += 1
			except:
				self.packets += 1
			self.mutex.release()

	def Printer(self, BSSID):
		screen = Drawer.drawer()

		while True:
			self.mutex.acquire()

			screen.clean()
			screen.print_label()
			screen.print_text(f"Attacking {BSSID} by RTS Flood Attack (type 'q' to stop)")

			# print(self.rts_packets/self.packets, self.rts_packets, self.packets)
			names = ["Malicious frames", "Usual frames"]
			values = [self.rts_packets/self.packets, (self.packets-self.rts_packets)/self.packets]

			plt.simple_bar(names, values, width=100, title='Attack efficiency')
			plt.show()

			self.mutex.release()
			sleep(self.timeout)

