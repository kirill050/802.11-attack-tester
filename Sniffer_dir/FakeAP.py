import os

class AP:
	
	dnsmasq_config="dnsmasq.conf"
	hostapd_config = "hostapd.conf"
	ssid = "MagicianSkull"
	channel="1"
	password="1234567890"

	def __init__(self, wirelessiface:str, gatewayiface:str="", ip:str="192.168.5.1",**kwargs):
		self.wirelessiface = wirelessiface
		self.gatewayiface = gatewayiface
		self.ip = ip
		for i in kwargs.keys():
			if getattr(self,i,None) != None:
				setattr(self,i,kwargs[i])

	def StopAp(self):
		os.system("pkill -9 -f dnsmasq")
		os.system("pkill -9 -f hostapd")

	def EnableInterface(self):
		os.system(f"ifconfig {self.wirelessiface} down")
		os.system(f"ip link set dev {self.wirelessiface} up")
		os.system(f"ifconfig {self.wirelessiface} {self.ip}/24")

	def GenerateDnsMasqConfig(self):
		with open(f"{self.dnsmasq_config}","w") as fp:
			fp.write(f"interface={self.wirelessiface}\n")
			fp.write(f"bind-interfaces\n")
			
			#шлюз - наша тд
			fp.write(f"dhcp-option=3,{self.ip}\n")
			#мы раздаём адреса dns 
			fp.write(f"dhcp-option=6,{self.ip}\n")

			
			startadr,endadr = self.GetRange()
			fp.write(f"dhcp-range={startadr},{endadr},12h\n")
			fp.write(f"no-hosts\nno-resolv\n")
			fp.write(f"log-queries\nlog-facility=/var/log/dnsmasq.log\n")

			fp.write(f"address=/example.com/{self.ip}\n")# тестирование редиректа хостов
			fp.write(f"server=8.8.8.8\nserver=8.8.4.4\n")# DNS сервера

	def GenerateHostApConfig(self):
		with open(f"{self.hostapd_config}","w") as fp:
			fp.write(f"ctrl_interface=/var/run/hostapd\n")
			fp.write(f"interface={self.wirelessiface}\n")
			fp.write(f"ssid={self.ssid}\n")
			fp.write(f"driver=nl80211\n")
			fp.write(f"channel={self.channel}\n")     
			fp.write(f"hw_mode=g\n")
			fp.write(f"ieee80211d=1\n")   
			fp.write(f"country_code=RU\n")
			fp.write(f"macaddr_acl=0\n")  
			fp.write(f"deny_mac_file=/etc/hostapd.deny\n")
			fp.write(f"wmm_enabled=0\n")  
			fp.write(f"auth_algs=1\n") 
			fp.write(f"wpa=2\n")
			fp.write(f"wpa_key_mgmt=WPA-PSK\n")  
			fp.write(f"rsn_pairwise=CCMP\n")
			fp.write(f"wpa_passphrase={self.password}\n")

	def GetRange(self):
		startadr = self.ip.split('.')
		endadr = self.ip.split('.')
		startadr[-1] = "2"
		endadr[-1] = "10"
		return ".".join(startadr) , ".".join(endadr)

	
	def launch(self):
		# убираем сервисы
		self.StopAp()

		self.EnableInterface()
		self.GenerateDnsMasqConfig()
		
		os.system(f"dnsmasq --conf-file={self.dnsmasq_config}")
		if self.gatewayiface != "":
			os.system(f"echo '1' > /proc/sys/net/ipv4/ip_forward")
			os.system(f"iptables -A FORWARD -i {self.gatewayiface} -o {self.wirelessiface} -m state --state ESTABLISHED,RELATED -j ACCEPT")
			os.system(f"iptables -A FORWARD -i {self.wirelessiface} -o {self.gatewayiface} -j ACCEPT")
			os.system(f"iptables -t nat -A POSTROUTING -o {self.gatewayiface} -j MASQUERADE")

		self.GenerateHostApConfig()
		os.system(f"hostapd {self.hostapd_config}")





ap = AP(wirelessiface="wlan0",ssid="HelloFriends")
ap.launch()







