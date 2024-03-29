import random
import threading

import keyboard
import multiprocessing
import time
import Attacker, Sniffer, Drawer

import signal
import sys, os
import argparse
from sys import platform
import psutil



class UI:
    def __init__(self, attack_int, control_int):
        self.screen = Drawer.drawer()
        self.attack_int = attack_int
        self.control_int = control_int
        self.attacks = [self.rts_flood, self.null_probe_response, self.rogue_twin, self.deauth, self.disassoc,
                        self.Omerta_Attack, self.AP_ass_table_overflow, self.fake_beacon]  # add new attack method here
        self.attacker = Attacker.attacker(self.attack_int)
        self.sniffer = Sniffer.sniffer(self.control_int, self.attack_int)

    def main_window(self):
        # add new attack method here
        raws =     [["0", "RTS flood",
                 "Floods RTS/CTS frames to reserve the RF medium and force other wireless devices sharing the RF medium to hold back their transmissions"]]
        raws.append(["1", "Null Probe Response", "Sending probe response containing a null SSID. Causes lock up upon receiving such a probe response"])
        raws.append(["2", "Rogue twin", "Creates fake AP with the same channel and SSID as target"])  # "✅" "❌"
        raws.append(["3", "Deauthentication attack", "Attempts to disconnect specific clients in range by sending deauth frames"])
        raws.append(["4", "Disassociation attack", "Attempts to disconnect specific clients in range by sending disassociation frames"])
        raws.append(["5", "Omerta Attack",
                     "Attempts to disconnect clients by sending disassociation frames with a reason code of 0x01 (“unspecified”) to all stations in wireless net"])
        raws.append(["6", "AP association table overflow", "Floods AP with association + authentication requests to overflow association table"])
        raws.append(["7", "Beacon Frame Spoofing",
                     "Spoofs a beacon packet on channels that are different from that advertised in the beacon frame of the AP."])
        raws.append(["8", "Coming soon", "..."])
        self.screen.draw_table(["No.", "Name", "Brief descr."], raws)

        attack = self.screen.get_input("Witch attack you wanna run? (type its number)", int)
        if attack in range(len(self.attacks)):
            self.attacks[attack]()

    def fake_beacon(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Beacon Frame Spoofing Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        while len(self.nets) == 0:
            self.screen.print_label()
            self.screen.print_text(f"No nets found at freq {Freq}!")
            if "y" in (self.screen.get_input("Rescan it? (y/n)", str)).lower():
                self.screen.clean()
                self.nets = self.sniffer.scan_nets_(Freq)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets,
                               '''Beacon Frame Spoofing Attack\n'''
                               '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")

        args = {"SSID":    self.nets[target_net][1],
                "BSSID":   self.nets[target_net][2],
                "Freq":    self.nets[target_net][3],
                "Channel": self.nets[target_net][4]
                }

        self.run_attack("fake_beacon", args["SSID"], args)

    def AP_ass_table_overflow(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''AP association table overflow Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        while len(self.nets) == 0:
            self.screen.print_label()
            self.screen.print_text(f"No nets found at freq {Freq}!")
            if "y" in (self.screen.get_input("Rescan it? (y/n)", str)).lower():
                self.screen.clean()
                self.nets = self.sniffer.scan_nets_(Freq)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets,
                               '''AP association table overflow Attack\n'''
                               '''Choose net(s) to be attacked''')
        target_nets = self.screen.get_input("Choose net(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        args = []
        target = []
        for net in (target_nets.replace(" ", "")).split(','):
            i = int(net)
            args.append({
                "SSID":    self.nets[i][1],
                "BSSID":   self.nets[i][2],
                "Freq":    self.nets[i][3],
                "Channel": self.nets[i][4]
            })
            target.append([self.nets[i][1], self.nets[i][2]])

        self.run_attack("AP_assoc_table_overflow", target, args)

    def Omerta_Attack(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Omerta Attack\n''')


        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets, '''Omerta Attack\n'''
                                                                                                    '''Choose net(s) to be attacked''')
        target_nets = self.screen.get_input("Choose net(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        target_info = []
        for net in (target_nets.replace(" ", "")).split(','):
            i = int(net)
            target_info.append([self.nets[i][2], self.nets[i][4], self.nets[i][1]])

        self.devices = self.sniffer.scan_devices_(Freq, target_info)
        while len(self.devices) == 0:
            self.screen.print_label()
            nets = []
            for i in range(len((target_nets.replace(" ", "")).split(','))):
                nets.append([self.nets[i][2], self.nets[i][4]])
            self.screen.print_text(f"No devices found at nets {nets}!")
            if "y" in (self.screen.get_input("Rescan them? (y/n)", str)).lower():
                self.screen.clean()
                self.devices = self.sniffer.scan_devices_(Freq, target_info)
            else:
                return

        self.screen.clean()

        target_devices = ""
        for i in range(len(self.devices)):
            for ii in range(len(target_info)):
                if self.devices[i][5] in target_info[ii]:
                    if len(target_devices) > 0:
                        target_devices += ','
                    target_devices += str(self.devices[i][0])

        args = []
        target = []
        for device in (target_devices.replace(" ", "")).split(','):
            i = int(device)
            args.append({
                "MAC":     self.devices[i][1],
                "BSSID":   self.devices[i][5],
                "Freq":    self.devices[i][2],
                "Channel": self.devices[i][3]
            })
            target.append([self.devices[i][4], self.devices[i][5]])

        self.run_attack("omerta_attack", target, args)

    def disassoc(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Disassociation Attack\n''')


        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets, '''Disassociation Attack\n'''
                                                                                                    '''Choose net(s) to be attacked''')
        target_nets = self.screen.get_input("Choose net(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        target_info = []
        for net in (target_nets.replace(" ", "")).split(','):
            i = int(net)
            target_info.append([self.nets[i][2], self.nets[i][4], self.nets[i][1]])

        self.devices = self.sniffer.scan_devices_(Freq, target_info)
        while len(self.devices) == 0:
            self.screen.print_label()
            nets = []
            for i in range(len((target_nets.replace(" ", "")).split(','))):
                nets.append([self.nets[i][2], self.nets[i][4]])
            self.screen.print_text(f"No devices found at nets {nets}!")
            if "y" in (self.screen.get_input("Rescan them? (y/n)", str)).lower():
                self.screen.clean()
                self.devices = self.sniffer.scan_devices_(Freq, target_info)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "MAC", "Freq", "Channel", "Net SSID", "Net BSSID"], self.devices,
                               '''Disassociation Attack\n'''
                               '''Choose device(s) to be attacked''')
        target_devices = self.screen.get_input("Choose device(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        args = []
        target = []
        for device in (target_devices.replace(" ", "")).split(','):
            i = int(device)
            args.append({
                "MAC":     self.devices[i][1],
                "BSSID":   self.devices[i][5],
                "Freq":    self.devices[i][2],
                "Channel": self.devices[i][3]
            })
            target.append(self.devices[i][1])

        self.run_attack("dissasoc", target, args)

    def deauth(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Deauthentication Attack\n''')


        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets, '''Deauthentication Attack\n'''
                                                                                                    '''Choose net(s) to be attacked''')
        target_nets = self.screen.get_input("Choose net(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        target_info = []
        for net in (target_nets.replace(" ", "")).split(','):
            i = int(net)
            target_info.append([self.nets[i][2], self.nets[i][4], self.nets[i][1]])

        self.devices = self.sniffer.scan_devices_(Freq, target_info)
        while len(self.devices) == 0:
            self.screen.print_label()
            nets = []
            for i in range(len((target_nets.replace(" ", "")).split(','))):
                nets.append([self.nets[i][2], self.nets[i][4]])
            self.screen.print_text(f"No devices found at nets {nets}!")
            if "y" in (self.screen.get_input("Rescan them? (y/n)", str)).lower():
                self.screen.clean()
                self.devices = self.sniffer.scan_devices_(Freq, target_info)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "MAC", "Freq", "Channel", "Net SSID", "Net BSSID"], self.devices,
                               '''Deauthentication Attack\n'''
                               '''Choose device(s) to be attacked''')
        target_devices = self.screen.get_input("Choose device(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        args = []
        target = []
        for device in (target_devices.replace(" ", "")).split(','):
            i = int(device)
            args.append({
                "MAC":     self.devices[i][1],
                "BSSID":   self.devices[i][5],
                "Freq":    self.devices[i][2],
                "Channel": self.devices[i][3]
            })
            target.append(self.devices[i][1])

        self.run_attack("deauth", target, args)

    def rogue_twin(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Rogue Twin Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        while len(self.nets) == 0:
            self.screen.print_label()
            self.screen.print_text(f"No nets found at freq {Freq}!")
            if "y" in (self.screen.get_input("Rescan it? (y/n)", str)).lower():
                self.screen.clean()
                self.nets = self.sniffer.scan_nets_(Freq)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets,
                               '''Rogue Twin Attack\n'''
                               '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")

        args = {"SSID":    self.nets[target_net][1],
                "BSSID":   self.nets[target_net][2],
                "Freq":    self.nets[target_net][3],
                "Channel": self.nets[target_net][4]
                }

        self.run_attack("rogue_twin", args["SSID"], args)

    def null_probe_response(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Null Probe Response Attack\n''')


        self.nets = self.sniffer.scan_nets_(Freq)
        while len(self.nets) == 0:
            self.screen.print_label()
            self.screen.print_text(f"No nets found at freq {Freq}!")
            if "y" in (self.screen.get_input("Rescan it? (y/n)", str)).lower():
                self.screen.clean()
                self.nets = self.sniffer.scan_nets_(Freq)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets, '''Null Probe Response Attack\n'''
                                                                                                    '''Choose net(s) to be attacked''')
        target_nets = self.screen.get_input("Choose net(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        target_info = []
        for net in (target_nets.replace(" ", "")).split(','):
            i = int(net)
            target_info.append([self.nets[i][2], self.nets[i][4], self.nets[i][1]])

        self.devices = self.sniffer.scan_devices_(Freq, target_info)
        while len(self.devices) == 0:
            self.screen.print_label()
            nets = []
            for i in range(len((target_nets.replace(" ", "")).split(','))):
                nets.append([self.nets[i][2], self.nets[i][4]])
            self.screen.print_text(f"No devices found at nets {nets}!")
            if "y" in (self.screen.get_input("Rescan them? (y/n)", str)).lower():
                self.screen.clean()
                self.devices = self.sniffer.scan_devices_(Freq, target_info)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "MAC", "Freq", "Channel", "Net SSID", "Net BSSID"], self.devices,
                               '''Null Probe Response Attack\n'''
                               '''Choose device(s) to be attacked''')
        target_devices = self.screen.get_input("Choose device(s) to be attacked (print digit or combination using commas \",\"):", var_type=str)

        args = []
        target = []
        for device in (target_devices.replace(" ", "")).split(','):
            i = int(device)
            args.append({
                "MAC":     self.devices[i][1],
                "BSSID":   self.devices[i][5],
                "Freq":    self.devices[i][2],
                "Channel": self.devices[i][3]
            })
            target.append(self.devices[i][1])
        self.run_attack("null_probe_response", target, args)

    def rts_flood(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''RTS Flood Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        while len(self.nets) == 0:
            self.screen.print_label()
            self.screen.print_text(f"No nets found at freq {Freq}!")
            if "y" in (self.screen.get_input("Rescan it? (y/n)", str)).lower():
                self.screen.clean()
                self.nets = self.sniffer.scan_nets_(Freq)
            else:
                return

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "PWR", "802.11 standart"], self.nets, '''RTS Flood Attack\n'''
                                                                                                    '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")

        args = {"SSID":    self.nets[target_net][1],
                "BSSID":   self.nets[target_net][2],
                "Freq":    self.nets[target_net][3],
                "Channel": self.nets[target_net][4]
                }

        self.run_attack("rts_flood", args["SSID"], args)  # attack must be equal
                                                  # to methods names in attacker and snifer classes!!!

    def run_attack(self, attack, target, args):
        self.screen.clean()
        self.screen.print_label()
        self.screen.print_text(f"Attacking {target} by {attack} (type 'q' to stop)")

        attack_proc = multiprocessing.Process(target=getattr(self.attacker, attack), args=(args, ))
        sniff_proc = multiprocessing.Process(target=getattr(self.sniffer, attack), args=(args,))

        sniff_proc.start()
        time.sleep(3)
        attack_proc.start()


        while True:
            if keyboard.is_pressed("q"):
                print("You pressed 'q'.")
                for i in [attack_proc, sniff_proc]:
                    parent = psutil.Process(i.pid)
                    for ii in parent.children(recursive=True):
                        ii.send_signal(signal.SIGTERM)
                    i.terminate()
                break

    def __ask_Freq(self, attack_name):
        self.sniffer.start_monitor_mode()
        self.screen.clean()

        self.frequencies = [["0", "2.4 GHz", "✅"]]
        self.frequencies.append(["1", "5 GHz", "✅"])
        self.frequencies.append(["2", "6 GHz", "❌"])

        self.screen.draw_table(["No.", "F", "Status"], self.frequencies, attack_name+'''Frequency''')
        Freq = self.screen.get_input("Witch frequency you`d like to attack? (print digit or combination using commas \",\")", str)
        Freq = (Freq.replace(" ", "")).replace(",", "")
        return Freq


def signal_handler(signum, frame):
    signal.signal(signum, signal.SIG_IGN)  # ignore additional signals
    exit(12)


if __name__ == "__main__":
    if "win" not in platform:
        if not 'SUDO_UID' in os.environ.keys():
            print("this program requires super user priv.")
            sys.exit(1)

    parser = argparse.ArgumentParser(description='802.11 attack tester',
                                     epilog='''Both attack and control interfaces should be able to be switched to monitor mode!!!
                                     ex. $python3 main.py wlan0 wlan1mon''')
    parser.add_argument('attack_interface', type=str, help='Attacking interface')
    parser.add_argument('control_interface', type=str, help='Quality analyzing (sniffing) interface')

    args = parser.parse_args()

    # if len(sys.argv) < 3:
    if args.attack_interface == "" or args.control_interface == "":
        parser.print_help()
        exit(0)
    else:
        attack_int = args.attack_interface
        control_int = args.control_interface
        # attack_int =  sys.argv[1]
        # control_int = sys.argv[2]
        print(attack_int, control_int)

    signal.signal(signal.SIGINT, signal_handler)

    program = UI(attack_int, control_int)

    while True:
        program.main_window()
