#!/usr/bin/env python3

from subprocess import Popen, PIPE
from scapy.all import *
from curses import *

class Application:
    def __init__(self):
        self.current = 0
        self.total = 0
        self.port = []
        self.eport = []
        self.name = '<UNKNOWN>'


def linux_command(command):
    return (Popen(command,stdout=PIPE).communicate()[0].decode('UTF-8')).split()

def get_interface():
    arp = linux_command(['cat','/proc/net/arp'])
    return arp[14]

def get_name(eport):
    lsof = linux_command(['lsof','-ni',":{}".format(eport)])
    if len(lsof):
        return lsof[9]
    else:
        return '<UNKNOWN>'

def packet_handler(pkt):
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        size = len(pkt)
        if pkt.sport > pkt.dport:
            eport=str(pkt.sport)
            port=str(pkt.dport)
        else:
            eport=str(pkt.dport)
            port=str(pkt.sport)
        if eport in tempportlist:
            for app in displaydata:
                if eport in app.eport:
                    if port not in app.port:
                        app.port.append(port)
                    app.current+=size
                    break
        else:
            name = get_name(eport)
            if name in namelist:
                for app in displaydata:
                    if name == app.name:
                        if port not in app.port:
                            app.port.append(port)
                        app.eport.append(eport)
                        app.current+=size
                        break
            else:
                new = Application()
                new.current = size
                new.total = size
                new.name = name
                new.port.append(port)
                new.eport.append(eport)
                tempportlist.append(eport)
                namelist.append(name)
                displaydata.append(new)

def sniff_packets(interface):
    sniff(iface = interface, timeout = 1, prn = packet_handler)

def b_to_kb(data):
    if data == 0:
        return 0
    else:
        if data > 49:
            return round(data/1000,1)
        else:
            return 0.1

def main(window):
    interface = get_interface()
    n = 'NAME:'
    c = 'CURRENT BANDWIDTH:'
    t = 'TOTAL BANDWIDTH:'
    p = 'PORTS:'
    whitespace = 5
    filler = len(n)
    while True:
        for app in displaydata:
            if len(app.name) > filler:
                filler = len(app.name)
        window.addstr(0, 0, n
        + (' ' * (filler - len(n) + whitespace)) + c
        + (' ' * whitespace) + t
        + (' ' * whitespace) + p)
        row = 1
        for app in displaydata:
            app.total = round(app.total + b_to_kb(app.current),1)
            window.addstr(row , 0, app.name
            + (' ' * (whitespace + filler - len(app.name)))
            + str(b_to_kb(app.current)) + ' KB / sec'
            + (' ' * (whitespace + len(c) - len(str(b_to_kb(app.current)) + ' KB / sec')))
            + str(app.total) + ' KB'
            + (' ' * (whitespace + len(t) - len(str(app.total) + ' KB')))
            + str(app.port)
            + (' ' * whitespace))
            app.current = 0
            app.eport.clear()
            row+=1
        window.refresh()
        tempportlist.clear()
        sniff_packets(interface)

if __name__ == '__main__':
    displaydata = []
    tempportlist = []
    default = Application()
    namelist = [default.name]
    displaydata.append(default)
    wrapper(main)
