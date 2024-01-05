import time
import multiprocessing

import Drawer
from Sniffer_dir import sniffer_main
# from Sniffer import sniffer
from Sniffer_dir.sniffer_main import ScanNetworks
from rich.progress import Progress


class sniffer:
    def __init__(self, control_int):
        self.control_int = control_int

    def __del__(self):
        self.screen = ""

    def rogue_twin(self, SSID, BSSID, Freq, Channel, attacking_addr='05:12:54:15:54:11'):
        sniffer_main.sniffer_start(self.control_int, attacking_addr, BSSID, Channel)
    def rts_flood(self, SSID, target_addr, Freq, Channel, attacking_addr='05:12:54:15:54:11'):
        sniffer_main.sniffer_start(self.control_int, attacking_addr, target_addr, Channel)

    def __PHY_scan(self, freq):
        nets = []

        sniffer = sniffer_main.Sniffer()
        sniffer.SetInterface(self.control_int)

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
                            if [ii["SSID"], ii["BSSID"], "2.4", ii["channel"], "n"] not in nets:
                                nets.append([ii["SSID"], ii["BSSID"], "2.4", ii["channel"], "n"])
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 2.4GHz")
                        err = True
                    progress.update(task, advance=1)
                if err:
                    nets.append(["Asus_Home_2G", "D2:73:3A:A9:1A:6C", "2.4", "5", "g"])
                    nets.append(["GPON_Home_2G", "D2:9A:D0:0B:66:21", "2.4", "7", "ac"])
                    nets.append(["Ole4ka_2G", "E3:55:EF:16:C5:3C", "2.4", "11", "ac"])
            if freq == "1":  # 5 GHz
                task = progress.add_task("[green]Scanning 5 GHz...", 152) # TODO count channels
                for i in range(152):
                    try:
                        nets.append(ScanNetworks(sniffer, [i]).values())
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 5 GHz")
                        err = True
                    self.screen.update_progress(task, 1)
                    time.sleep(0.05)
                if err:
                    nets.append(["GPON_Home_5G", "D2:9A:D0:0B:66:22", "5", "48", "ac"])
                    nets.append(["Ole4ka_5G", "E3:55:EF:16:C5:3D", "5", "111", "ac"])
            if freq == "2":  # 6 GHz
                task = progress.add_task("[blue]Scanning 6 GHz...", 200) # TODO count channels
                for i in range(200):
                    try:
                        nets.append(ScanNetworks(sniffer, [i]).values())
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 6 GHz")
                        err = True
                    self.screen.update_progress(task, 1)
                    time.sleep(0.03)
                if err:
                    nets.append(["GPON_Home_6G", "D2:9A:D0:0B:66:23", "6", "129", "ax"])
                    nets.append(["Ole4ka_6G", "E3:55:EF:16:C5:3E", "6", "10", "ax"])
        return nets

    def __PHY_scan_devices(self, freq): #TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        nets = []

        sniffer = sniffer_main.Sniffer()
        sniffer.SetInterface(self.control_int)

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
                            if [ii["SSID"], ii["BSSID"], "2.4", ii["channel"], "n"] not in nets:
                                nets.append([ii["SSID"], ii["BSSID"], "2.4", ii["channel"], "n"])
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 2.4GHz")
                        err = True
                    progress.update(task, advance=1)
                if err:
                    nets.append(["Asus_Home_2G", "D2:73:3A:A9:1A:6C", "2.4", "5", "g"])
                    nets.append(["GPON_Home_2G", "D2:9A:D0:0B:66:21", "2.4", "7", "ac"])
                    nets.append(["Ole4ka_2G", "E3:55:EF:16:C5:3C", "2.4", "11", "ac"])
            if freq == "1":  # 5 GHz
                task = progress.add_task("[green]Scanning 5 GHz...", 152) # TODO count channels
                for i in range(152):
                    try:
                        nets.append(ScanNetworks(sniffer, [i]).values())
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 5 GHz")
                        err = True
                    self.screen.update_progress(task, 1)
                    time.sleep(0.05)
                if err:
                    nets.append(["GPON_Home_5G", "D2:9A:D0:0B:66:22", "5", "48", "ac"])
                    nets.append(["Ole4ka_5G", "E3:55:EF:16:C5:3D", "5", "111", "ac"])
            if freq == "2":  # 6 GHz
                task = progress.add_task("[blue]Scanning 6 GHz...", 200) # TODO count channels
                for i in range(200):
                    try:
                        nets.append(ScanNetworks(sniffer, [i]).values())
                    except Exception as e:
                        print(f"Error {e} while scanning chanel {i} on 6 GHz")
                        err = True
                    self.screen.update_progress(task, 1)
                    time.sleep(0.03)
                if err:
                    nets.append(["GPON_Home_6G", "D2:9A:D0:0B:66:23", "6", "129", "ax"])
                    nets.append(["Ole4ka_6G", "E3:55:EF:16:C5:3E", "6", "10", "ax"])
        return nets

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
    def scan_devices_(self, freq):
        devices = []
        if "0" in freq:  # 2.4 GHz
            subdevices = self.__PHY_scan_devices("0")
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        if "1" in freq:  # 5 GHz
            subdevices = self.__PHY_scan_devices("1")
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        if "2" in freq:  # 6 GHz
            subdevices = self.__PHY_scan_devices("2")
            for net in subdevices:
                devices.append([str(len(devices)), *net])
        return devices

    def start_monitor_mode(self, interface):
        print(f"iwconfig {interface}...")

    def change_channel(self, interface):
        print(f"iwconfig {interface}...")
