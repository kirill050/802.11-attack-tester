import time
import multiprocessing

import Drawer
from Sniffer_dir import sniffer_main
# from Sniffer import sniffer
from Sniffer_dir.sniffer_main import ScanNetworks, ScanNetwork_for_Devices
from rich.progress import Progress
from Sniffer_dir.common import bash
from sys import platform
if "win" not in platform:
    import netifaces
from Sniffer_dir.iface import *
from Sniffer_dir.common import *

class sniffer:
    def __init__(self, control_int, attack_int = ""):
        self.control_int = control_int
        self.attack_int = attack_int


    def __del__(self):
        self.screen = ""

    def rogue_twin (self, args: dict):
        # bssid_fake = bash(f"ifconfig {self.attack_int}"+" | grep ether | gawk '{print $2}'")
        bssid_fake = netifaces.ifaddresses(self.attack_int)[netifaces.AF_LINK][0]["addr"]
        sniffer_main.sniffer_start_AP_analyzer(self.control_int, bssid_real=str(args["BSSID"]).lower(), bssid_fake=bssid_fake,
                                               channel=int(args["Channel"]))

    def rts_flood(self, args: dict):
        if "attacking_addr" in args.keys():
            attacking_addr = args["attacking_addr"]
        else:
            attacking_addr = '05:12:54:15:54:11'
        sniffer_main.sniffer_start_RTS_analyzer(self.control_int, attacking_addr, str(args["BSSID"]).lower(), int(args["Channel"]))

    def null_probe_response(self, args: list[dict]):
        targets = []
        channels = []
        for device in args:
            targets.append(device["MAC"])
            if int(device["Channel"]) not in channels:
                channels.append(int(device["Channel"]))
        sniffer_main.sniffer_start_NPR_Analyzer(self.control_int, targets, channels)

    def deauth(self, args: list[dict]):
        targets = []
        channels = []
        for device in args:
            targets.append(device["MAC"])
            if int(device["Channel"]) not in channels:
                channels.append(int(device["Channel"]))
        sniffer_main.sniffer_start_Deauth_Dissasoc_Analyzer(self.control_int, subtype=12,
                                                            targets=targets, channels=channels,
                                                            attack_name="Deauthentication Attack")

    def dissasoc(self, args: list[dict]):
        targets = []
        channels = []
        for device in args:
            targets.append(device["MAC"])
            if int(device["Channel"]) not in channels:
                channels.append(int(device["Channel"]))
        sniffer_main.sniffer_start_Deauth_Dissasoc_Analyzer(self.control_int, subtype=10,
                                                            targets=targets, channels=channels,
                                                            attack_name="Disassociation Attack")

    def omerta_attack(self, args: list[dict]):
        targets = []
        channels = []
        for device in args:
            if device["BSSID"] not in targets:
                targets.append(device["BSSID"])
            if int(device["Channel"]) not in channels:
                channels.append(int(device["Channel"]))
        sniffer_main.sniffer_start_Deauth_Dissasoc_Analyzer(self.control_int, subtype=10,
                                                            targets=targets, channels=channels,
                                                            attack_name="Omerta Attack")

    def AP_assoc_table_overflow(self, args: list[dict]):
        targets = []
        channels = []
        for net in args:
            targets.append(net["BSSID"])
            if int(net["Channel"]) not in channels:
                channels.append(int(net["Channel"]))
        sniffer_main.sniffer_start_AP_assoc_table_overflow_Analyzer(self.control_int, targets=targets, channels=channels)



    def __PHY_scan(self, freq):
        nets = []


        if "win" in platform:
            nets.append(["Asus_Home_2G", "D2:73:3A:A9:1A:6C", "2.4", "5", "g"])
            nets.append(["GPON_Home_2G", "D2:9A:D0:0B:66:21", "2.4", "7", "ac"])
            nets.append(["Ole4ka_2G", "E3:55:EF:16:C5:3C", "2.4", "11", "ac"])
            return nets

        sniffer = sniffer_main.Sniffer()
        sniffer.SetInterface(self.control_int)
        sniffer.EnableMonitor()

        screen = Drawer.drawer()

        with Progress() as progress:
            err = False  # TODO for tests
            if freq == "0":  # 2.4 GHz
                screen.print_text("Scanning 2.4 GHz...", "red")
                task = progress.add_task("[red]Scanning 2.4 GHz...", total=13)
                for i in range(1, 14):
                    progress.update(task, description=f"[red]Trying channel {i}")
                    try:
                        scan_results = ScanNetworks(sniffer, [i])
                        for ii in scan_results.values():
                            if [ii["SSID"], ii["BSSID"], "2.4", ii["channel"], ii["PWR"], ii["Standart"]] not in nets:
                                nets.append([ii["SSID"], ii["BSSID"], "2.4", ii["channel"], ii["PWR"], ii["Standart"]])
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 2.4GHz")
                        err = True
                    progress.update(task, advance=1)
                # if err:
                #     nets.append(["Asus_Home_2G", "D2:73:3A:A9:1A:6C", "2.4", "5", "g"])
                #     nets.append(["GPON_Home_2G", "D2:9A:D0:0B:66:21", "2.4", "7", "ac"])
                #     nets.append(["Ole4ka_2G", "E3:55:EF:16:C5:3C", "2.4", "11", "ac"])
            if freq == "1":  # 5 GHz
                screen.print_text("Scanning 5 GHz...", "green")
                task = progress.add_task("[green]Scanning 5 GHz...", total=20)
                for i in ( list(range(32, 69, 4)) + list(range(132, 145, 4)) + list(range(149, 170, 4))  ):
                    progress.update(task, description=f"[green]Trying channel {i}")
                    try:
                        scan_results = ScanNetworks(sniffer, [i])
                        for ii in scan_results.values():
                            if [ii["SSID"], ii["BSSID"], "5", ii["channel"], ii["PWR"], ii["Standart"]] not in nets:
                                nets.append([ii["SSID"], ii["BSSID"], "5", ii["channel"], ii["PWR"], ii["Standart"]])
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 5 GHz")
                    progress.update(task, advance=2)
                    # time.sleep(0.02)
                # if err:
                #     nets.append(["GPON_Home_5G", "D2:9A:D0:0B:66:22", "5", "48", "ac"])
                #     nets.append(["Ole4ka_5G", "E3:55:EF:16:C5:3D", "5", "111", "ac"])
                screen.print_text("5 GHz frequency is currently not supported! Work in progress...", "red")
            if freq == "2":  # 6 GHz
                screen.print_text("Scanning 6 GHz...", "blue")
                task = progress.add_task("[blue]Scanning 6 GHz...", total=200) # TODO count channels
                for i in range(200):
                    try:
                        progress.update(task, description=f"[blue]Trying channel {i}")
                        # nets.append(ScanNetworks(sniffer, [i]).values())
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 6 GHz")
                        err = True
                    progress.update(task, advance=1)
                    time.sleep(0.01)
                screen.print_text("6 GHz frequency is currently not supported! Work in progress...", "red")
                # if err:
                #     nets.append(["GPON_Home_6G", "D2:9A:D0:0B:66:23", "6", "129", "ax"])
                #     nets.append(["Ole4ka_6G", "E3:55:EF:16:C5:3E", "6", "10", "ax"])
        return nets

    def __PHY_scan_devices(self, freq, target_info):
        devices = []

        sniffer = sniffer_main.Sniffer()
        sniffer.SetInterface(self.control_int)

        screen = Drawer.drawer()

        with Progress() as progress:
            if freq == "0":  # 2.4 GHz
                screen.print_text("Scanning for devices on 2.4 GHz...", "red")
                task = progress.add_task("[red]Scanning for devices on 2.4 GHz...",
                                         total=len(target_info))
                for i in range(len(target_info)):
                    if target_info[i][1] not in range(1, 14):
                        continue
                    progress.update(task, description=f"[red]Scanning {target_info[i][2]}:{target_info[i][0]} on channel {target_info[i][1]}...")
                    try:
                        scan_results = ScanNetwork_for_Devices(sniffer, BSSID=target_info[i][0], channel=target_info[i][1])
                        for iii in scan_results:
                            if [iii, "2.4", target_info[i][1], target_info[i][2], target_info[i][0]] not in devices:
                                devices.append([iii, "2.4", target_info[i][1], target_info[i][2], target_info[i][0]])
                    except Exception as e:
                        print(f"Error {e} while scanning {target_info[i][2]}:{target_info[i][0]} on channel {target_info[i][1]} on 2.4GHz")
                    progress.update(task, advance=1)
            if freq == "1":  # 5 GHz
                screen.print_text("Scanning for devices on 5 GHz...", "green")
                task = progress.add_task("[green]Scanning for devices on 5 GHz...", total=len(target_info))
                for i in range(len(target_info)):
                    if target_info[i][1] not in range(32, 178):
                        continue
                    progress.update(task,
                                    description=f"[green]Scanning {target_info[i][2]}:{target_info[i][0]} on channel {target_info[i][1]}...")
                    try:
                        scan_results = ScanNetwork_for_Devices(sniffer, BSSID=target_info[i][0],
                                                               channel=target_info[i][1])
                        for iii in scan_results:
                            if [iii, "5", target_info[i][1], target_info[i][2], target_info[i][0]] not in devices:
                                devices.append([iii, "5", target_info[i][1], target_info[i][2], target_info[i][0]])
                    except Exception as e:
                        print(f"Error {e} while scanning {target_info[i][2]}:{target_info[i][0]} on channel {target_info[i][1]} on 5GHz")
                    progress.update(task, advance=1)
                print("5 GHz frequency is currently not supported! Work in progress...")
                # if err:
                #     devices.append(["GPON_Home_5G", "D2:9A:D0:0B:66:22", "5", "48", "ac"])
                #     devices.append(["Ole4ka_5G", "E3:55:EF:16:C5:3D", "5", "111", "ac"])
            if freq == "2":  # 6 GHz
                screen.print_text("Scanning 6 GHz...", "blue")
                task = progress.add_task("[blue]Scanning 6 GHz...", total=200) # TODO count channels
                for i in range(200):
                    try:
                        # devices.append(ScanNetworks(sniffer, [i]).values())
                        progress.update(task, description=f"[blue]Trying channel {i}")
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 6 GHz")
                        err = True
                    progress.update(task, advance=1)
                    time.sleep(0.03)
                print("6 GHz frequency is currently not supported! Work in progress...")
                # if err:
                #     devices.append(["GPON_Home_6G", "D2:9A:D0:0B:66:23", "6", "129", "ax"])
                #     devices.append(["Ole4ka_6G", "E3:55:EF:16:C5:3E", "6", "10", "ax"])
        return devices

    def scan_nets_(self, freq):
        nets = []
        if "0" in freq:  # 2.4 GHz
            subnets = self.__PHY_scan("0")
            for net in subnets:
                nets.append([str(len(nets)), *net])
        if "1" in freq:  # 5 GHz
            subnets = self.__PHY_scan("1")
            for net in subnets:
                nets.append([str(len(nets)), *net])
        if "2" in freq:  # 6 GHz
            subnets = self.__PHY_scan("2")
            for net in subnets:
                nets.append([str(len(nets)), *net])
        return nets
    def scan_devices_(self, freq, target_info):
        devices = []
        if "0" in freq:  # 2.4 GHz
            subdevices = self.__PHY_scan_devices("0", target_info)
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        if "1" in freq:  # 5 GHz
            subdevices = self.__PHY_scan_devices("1", target_info)
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        if "2" in freq:  # 6 GHz
            subdevices = self.__PHY_scan_devices("2", target_info)
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        return devices

    def GetInterfaces(self):
        retval = []
        p = Path(INTERFACESPATH)
        for i in os.listdir(INTERFACESPATH):
            for iface in os.listdir(p / i / INTERFACESPATHAPPENDIX):
                retval.append(iface)
        return retval

    def start_monitor_mode(self):
        bash(f"airmon-ng check kill > /dev/null")
        bash(f"airmon-ng start {self.control_int} > /dev/null")
        for i in self.GetInterfaces():
            if self.control_int in i:
                self.control_int = i
                return i

        return None

    def change_channel(self, interface):
        print(f"iwconfig {interface}...")
