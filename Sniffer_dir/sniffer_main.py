from Sniffer_dir.sniff import *
from Sniffer_dir.analyzer import *
from Sniffer_dir.scanner import *


packets_q = queue.Queue()


def ScanNetworks(sniffer: Sniffer, channels: list[int]):
	wifiscaner = WIFIScanner(sniffer)
	for i in channels:
		wifiscaner.sniffer.SetChannel(i)
		wifiscaner.scan(timeout=10)

	networks = wifiscaner.GetNetworksInfo() 
	# пример итерации по информации о сетях
	# for i in networks.keys():
	# 	print(networks[i])
	return networks


def MonitorCts(pkt):
	packets_q.put_nowait(pkt)




def sniffer_start_RTS_analyzer(interface, attacking_addr, target_addr, channel: int = 1):
	sniffer = Sniffer(interface)

	# ifaces = sniffer.GetInterfaces()
	# sniffer.SetInterface(ifaces[0]) # просто берём первый из списка

	if not sniffer.IsMonitor():
		if sniffer.EnableMonitor() is None:
			print("ERROR enabling monitor mode!!!")
			return
	sniffer.SetInterface(interface)

	# ScanNetworks(sniffer, [3, 44, 11, 6])

	sniffer.SetChannel(channel)
	a = RTS_Analyzer(1)
	collector_thread = threading.Thread(target=a.Analyzer, args=(packets_q, attacking_addr, target_addr), daemon=True).start()
	printer_thread = threading.Thread(target=a.Printer, args=(target_addr,), daemon=True).start()
	sniffer.exec(prn=MonitorCts, timeout=100)
	print("Started network scanning")


def sniffer_start_AP_analyzer(interface, bssid_real, bssid_fake, channel: int = 1):
	sniffer = Sniffer(interface)

	if not sniffer.IsMonitor():
		if sniffer.EnableMonitor() is None:
			print("ERROR enabling monitor mode!!!")
			return
	sniffer.SetInterface(interface)

	sniffer.SetChannel(channel)
	a = AP_Analyzer(bssid_real=bssid_real, bssid_fake=bssid_fake)
	collector_thread = threading.Thread(target=a.Analyzer, args=(packets_q, ), daemon=True).start()
	printer_thread = threading.Thread(target=a.Printer, args=(bssid_real,), daemon=True).start()
	sniffer.exec(prn=MonitorCts, timeout=100)
	print("Started network scanning")
