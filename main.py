import random

import keyboard
import multiprocessing
import time
import Attacker, Sniffer, Drawer

import signal
import sys, os
import argparse
from sys import platform



class UI:
    def __init__(self, attack_int, control_int):
        self.screen = Drawer.drawer()
        self.attack_int = attack_int
        self.control_int = control_int
        self.attacks = [self.rts_flood, self.null_probe_response, self.rogue_twin]
        self.attacker = Attacker.attacker(self.attack_int)
        self.sniffer = Sniffer.sniffer(self.control_int)

    def main_window(self):
        raws = [["0", "RTS flood",
                 "Floods RTS/CTS frames to reserve the RF medium and force other wireless devices sharing the RF medium to hold back their transmissions"]]
        raws.append(["1", "Null Probe Response", "❌"])
        raws.append(["2", "Rogue twin", "❌"])  # "✅"
        raws.append(["3", "Coming soon", "..."])
        self.screen.draw_table(["No.", "Name", "Brief descr."], raws)

        self.attacks[self.screen.get_input("Witch attack you wanna run?", int)]()

    def null_probe_response(self):
        print("null_probe_response")

    def rogue_twin(self):
        print("rogue_twin")

    def rts_flood(self):
        self.screen.clean()

        Freq = self.__ask_Freq()

        self.nets = self.sniffer.scan_nets_(Freq)

        self.screen.clean()

        self.screen.draw_table(["No.", "SSID", "BSSID", "Freq", "Channel", "802.11 standart"], self.nets, '''RTS Flood Attack\n'''
                                                                                                    '''Choose net to be attacked''')
        target_net = self.screen.get_input("Choose net to be attacked (type its number):")
        print(target_net)

        self.run_attack("rts_flood", target_net)  # attack must be equal
                                                  # to methods names in attacker and snifer classes!!!

    def run_attack(self, attack, target_net):
        self.screen.clean()
        self.screen.print_label()
        self.screen.print_text(f"Attacking {self.nets[target_net][2]} by {attack} (type 'q' to stop)")

        attack_proc = multiprocessing.Process(target=getattr(self.attacker, attack), args=(self.nets[target_net][2],
                                                                                           self.nets[target_net][3],
                                                                                           self.nets[target_net][4]))
        sniff_proc = multiprocessing.Process(target=getattr(self.sniffer, attack), args=(self.nets[target_net][2],
                                                                                         self.nets[target_net][3],
                                                                                         self.nets[target_net][4]))
        attack_proc.start()
        sniff_proc.start()

        while True:
            if keyboard.is_pressed("q"):
                print("You pressed 'q'.")
                attack_proc.terminate()
                sniff_proc.terminate()
                break

    def __ask_Freq(self):
        self.screen.clean()

        self.frequencies = [["0", "2.4 GHz"]]
        self.frequencies.append(["1", "5 GHz"])
        self.frequencies.append(["2", "6 GHz"])

        self.screen.draw_table(["No.", "F"], self.frequencies, '''RTS Flood Attack\n'''
                                                              '''Frequency''')
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
        # print('''Call this prog with 2 args:\n '''
        #       ''' 1) attacking wireless interface\n'''
        #        '''2) control wireless interface\n'''
        #       ''' ex. "python3 tester.py wlan0 wlan1mon"''')
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
