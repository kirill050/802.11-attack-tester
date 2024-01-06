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
        self.attacks = [self.rts_flood, self.null_probe_response, self.rogue_twin]
        self.attacker = Attacker.attacker(self.attack_int)
        self.sniffer = Sniffer.sniffer(self.control_int, self.attack_int)

    def main_window(self):
        raws = [["0", "RTS flood",
                 "Floods RTS/CTS frames to reserve the RF medium and force other wireless devices sharing the RF medium to hold back their transmissions"]]
        raws.append(["1", "Null Probe Response", "❌"])
        raws.append(["2", "Rogue twin", "Creates fake AP with the same channel and SSID as target"])  # "✅"
        raws.append(["3", "Coming soon", "..."])
        self.screen.draw_table(["No.", "Name", "Brief descr."], raws)

        self.attacks[self.screen.get_input("Witch attack you wanna run?", int)]()

    def null_probe_response(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Null Probe Response Attack\n''')


        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "802.11 standart"], self.nets, '''Null Probe Response Attack\n'''
                                                                                                    '''Choose net to be attacked''')
        target_nets = self.screen.get_input("Choose nets to be attacked (print digit or combination):")
        print(target_nets)

        target_info = []
        print("target_BSSIDs:")
        for i in target_nets:
            target_info.append([self.nets[i][2], self.nets[i][4], self.nets[i][1]])
            print([self.nets[i][2], self.nets[i][4]])

        self.devices = self.sniffer.scan_devices_(Freq, target_info)

        self.screen.clean()

        self.screen.draw_table(["No.", "MAC", "Freq", "Channel", "Net SSID", "Net BSSID"], self.devices,
                               '''Null Probe Response Attack\n'''
                               '''Choose device to be attacked''')
        target_device = self.screen.get_input("Choose device to be attacked (print digit or combination):")
        print(target_device)

        self.run_attack("null_probe_response", target_device)

    def rogue_twin(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''Rogue Twin Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "802.11 standart"], self.nets,
                               '''Rogue Twin Attack\n'''
                               '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")
        print(target_net)

        args = {"SSID":    self.nets[target_net][1],
                "BSSID":   self.nets[target_net][2],
                "Freq":    self.nets[target_net][3],
                "Channel": self.nets[target_net][4]
                }

        self.run_attack("rogue_twin", args["SSID"], args)

    def rts_flood(self):
        self.screen.clean()

        Freq = self.__ask_Freq('''RTS Flood Attack\n''')

        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "802.11 standart"], self.nets, '''RTS Flood Attack\n'''
                                                                                                    '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")
        print(target_net)

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

        self.frequencies = [["0", "2.4 GHz"]]
        self.frequencies.append(["1", "5 GHz"])
        self.frequencies.append(["2", "6 GHz"])

        self.screen.draw_table(["No.", "F"], self.frequencies, attack_name+'''Frequency''')
        Freq = self.screen.get_input("Witch frequency you`d like to attack? (print digit or combination)", str)
        print(Freq)
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
