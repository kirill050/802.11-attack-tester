from scapy.all import * 
import os
import sys
from datetime import datetime
from pathlib import Path
import datetime
import threading
import queue
from Sniffer_dir.iface import *


			
class Sniffer:
	def __init__(self, interface="wlp1s0"):
		self.interface = interface
		self.packets = 0

	def IsMonitor(self):
		if int(getMode(self.interface)) == 0:
			return True
		return False


	def EnableMonitor(self): # возвращает имя интерфейса после его перевода в режим монитора 
		bash(f"airmon-ng check kill")
		bash(f"airmon-ng start {self.interface}")
		for i in self.GetInterfaces():
			if self.interface in i:
				self.interface = i
				return i

		return None

	def SetInterface(self, interface: str):
		self.interface = interface

	def SetChannel(self, channel: int = 1):
		bash(f"iwconfig {self.interface} channel {channel}")

	def GetInterfaces(self):
		retval = []
		p = Path(INTERFACESPATH)
		for i in os.listdir(INTERFACESPATH):
			for iface in os.listdir(p/i/INTERFACESPATHAPPENDIX):
				retval.append(iface)
		return retval

	def exec(self, **kwargs):
		sniff(iface=self.interface, **kwargs)










