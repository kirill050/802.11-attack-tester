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



class AP_Analyzer:

	bssid_real = "ff:ff:ff:ff:ff:ff"
	bssid_fake = "ff:ff:ff:ff:ff:ff"
	mutex = threading.Lock()
	true_packets = 0
	our_packets = 0
	packets = 1
	timeout = 4

	def __init__(self, **kwargs):
		for i in kwargs.keys():
			if getattr(self, i, None) is not None:
				setattr(self, i, kwargs[i])

	def Analyzer(self, q:queue.Queue, *args):
		while True:
			packet = q.get()
			if packet.haslayer("Dot11FCS"):
				adr1 = packet["Dot11FCS"].addr1
				adr2 = packet["Dot11FCS"].addr2
				adr3 = packet["Dot11FCS"].addr3
				adr4 = packet["Dot11FCS"].addr4
				self.mutex.acquire()
				if self.bssid_fake in [adr1, adr2, adr3, adr4]:
					self.our_packets += 1
					self.packets += 1
				if self.bssid_real in [adr1, adr2, adr3, adr4]:
					self.true_packets += 1
					self.packets += 1
				self.mutex.release()

	def Printer(self, BSSID):
		screen = Drawer.drawer()
		while True:
			self.mutex.acquire()
			screen.clean()
			screen.print_label()
			screen.print_text(f"Attacking {BSSID} by Rogue Twin Attack (type 'q' to stop)")
			names = ["Frames real AP", "Frames fake AP"]
			values = [self.true_packets/self.packets, self.our_packets/self.packets]
			plt.simple_bar(names, values, width=100, title='Attack efficiency')
			plt.show()
			self.mutex.release()
			sleep(self.timeout)

class NPR_Analyzer:

	targets = ["ff:ff:ff:ff:ff:ff"]
	mutex = threading.Lock()
	packets = []
	TCM_number = 0  # The technological cycle of management
	timeout = 7

	def __init__(self, **kwargs):
		for i in kwargs.keys():
			if getattr(self, i, None) is not None:
				setattr(self, i, kwargs[i])
		for i in self.targets:
			self.packets.append([0])

	def Analyzer(self, q: queue.Queue):
		while True:
			packet = q.get()
			self.mutex.acquire()
			if packet.haslayer("Dot11FCS"):
				if not (packet["Dot11FCS"].type == 0 and packet["Dot11FCS"].subtype == 0x5):  # Probe response
					if not (packet["Dot11FCS"].type == 0 and packet["Dot11FCS"].subtype == 12):  # Deauth
						for target_addr in self.targets:
							if packet["Dot11FCS"].addr1 == target_addr or packet["Dot11FCS"].addr2 == target_addr or \
									packet["Dot11FCS"].addr3 == target_addr:
								self.packets[self.targets.index(target_addr)][self.TCM_number] += 1
			self.mutex.release()

	def Printer(self, MACs):
		screen = Drawer.drawer()
		while True:
			self.mutex.acquire()
			plt.clear_data()
			screen.clean()
			screen.print_label()
			for i in range(len(self.targets)):
				plt.plot(self.packets[i], label=MACs[i])
			plt.xlabel("Number of the technological cycle of management number")
			plt.ylabel("Number of packets by device")
			plt.title(f"Attacking {MACs} by Null Probe Response Attack (type 'q' to stop)")
			plt.show()

			for i in range(len(self.targets)):
				self.packets[i].append(0)
			self.TCM_number += 1

			self.mutex.release()
			sleep(self.timeout)

class Deauth_Dissasoc_Analyzer:

	targets = ["ff:ff:ff:ff:ff:ff"]
	mutex = threading.Lock()
	packets = []
	TCM_number = 0  # The technological cycle of management
	timeout = 7
	subtype = 12

	def __init__(self, **kwargs):
		for i in kwargs.keys():
			if getattr(self, i, None) is not None:
				setattr(self, i, kwargs[i])
		for i in self.targets:
			self.packets.append([0])

	def Analyzer(self, q: queue.Queue):
		while True:
			packet = q.get()
			self.mutex.acquire()
			if packet.haslayer("Dot11FCS"):
				if not (packet["Dot11FCS"].type == 0 and packet["Dot11FCS"].subtype == self.subtype):
					for target_addr in self.targets:
						if packet["Dot11FCS"].addr1 == target_addr or packet["Dot11FCS"].addr2 == target_addr or \
								packet["Dot11FCS"].addr3 == target_addr:
							self.packets[self.targets.index(target_addr)][self.TCM_number] += 1
			self.mutex.release()

	def Printer(self, MACs, attack_name):
		screen = Drawer.drawer()
		while True:
			self.mutex.acquire()
			plt.clear_data()
			screen.clean()
			screen.print_label()
			screen.print_text(f"Attacking {MACs} by {attack_name} (type 'q' to stop)")
			for i in range(len(self.targets)):
				plt.plot(self.packets[i], label=MACs[i])
			plt.xlabel("Number of the technological cycle of management")
			plt.ylabel("Number of packets by device")
			plt.title(f"Attacking {MACs} by Deauthentication Attack (type 'q' to stop)")
			plt.show()

			for i in range(len(self.targets)):
				self.packets[i].append(0)
			self.TCM_number += 1

			self.mutex.release()
			sleep(self.timeout)
