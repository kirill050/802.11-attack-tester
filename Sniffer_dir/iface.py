from Sniffer_dir.common import *
from Sniffer_dir.constants import *
from pathlib import Path


def getMode(ifacename: str):
    p = Path(INTERFACESPATH)
    for i in os.listdir(INTERFACESPATH):
        for iface in os.listdir(p / i / INTERFACESPATHAPPENDIX):
            if iface == ifacename:
                with open(p / i / INTERFACESPATHAPPENDIX / iface / "link_mode", "r") as fp:
                    mode = fp.read()
                    return mode
