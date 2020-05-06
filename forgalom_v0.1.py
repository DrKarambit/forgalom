#!/usr/bin/env python3

from subprocess import Popen, PIPE
from scapy.all import *
from curses import *

class CapturedPacket:
    def __init__(self, size, port1, port2):
        self.size = size
        if port1 > port2:
            self.eport = port1
            self.port = port2
        else:
            self.eport = port2
            self.port = port1


class Application:
    def __init__(self, name, current, total):
        self.name = name
        self.current = current
        self.total = total
        self.port = []
        self.eport = []


def linux_command(command):
    return (Popen(command,stdout=PIPE).communicate()[0].decode('UTF-8')).split()

def get_port_range():
    range = linux_command(['cat','/proc/sys/net/ipv4/ip_local_port_range'])
    return int(range[0])

def get_interface():
    arp = linux_command(['cat','/proc/net/arp'])
    return arp[14]

def get_name(eport):
    for app in displaydata:
        if eport in app.eport:
            return app.name
    lsof = linux_command(['lsof','-ni',":{}".format(eport)])
    if len(lsof):
        return lsof[9]
    else:
        return '<UNKNOWN>'

def packet_handler(pkt):
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        cp = CapturedPacket(size=len(pkt), port1=pkt.sport, port2=pkt.dport)
        if cp.eport >= portrange:
            currentdata.append(cp)

def sniff_packets(interface):
    sniff(iface = interface, timeout = 1, prn = packet_handler)

def b_to_mb(data):
    if data > 49999:
        return round(data/1000000,1)
    else:
        return 0.1

def main(window):
    interface = get_interface()
    while True:
        for pkt in currentdata:
            name = get_name(pkt.eport)
            if name not in applist:
                applist.append(name)
                new = Application(name=name, current=b_to_mb(pkt.size), total=b_to_mb(pkt.size))
                new.port.append(str(pkt.port))
                new.eport.append(str(pkt.eport))
                displaydata.append(new)
            else:
                for app in displaydata:
                    if name == app.name:
                        app.current = round(app.current+b_to_mb(pkt.size),1)
                        app.total = round(app.total+b_to_mb(pkt.size),1)
                        if str(pkt.port) not in app.port:
                            app.port.append(str(pkt.port))
                        break
        n = 'NAME:'
        c = 'CURRENT BANDWIDTH:'
        t = 'TOTAL BANDWIDTH:'
        p = 'PORTS:'
        whitespace = 5
        filler = len(n)
        for appname in applist:
            if len(appname) > filler:
                filler = len(appname)
        window.addstr(0, 0, n
        + (' ' * (filler - len(n) + whitespace)) + c
        + (' ' * whitespace) + t
        + (' ' * whitespace) + p)
        row = 1
        for app in displaydata:
            window.addstr(row , 0, app.name
            + (' ' * (whitespace + filler - len(app.name)))
            + str(app.current) + ' MB / sec'
            + (' ' * (whitespace + len(c) - len(str(app.current) + ' MB / sec')))
            + str(app.total) + ' MB'
            + (' ' * (whitespace + len(t) - len(str(app.total) + ' MB')))
            + str(app.port)
            + (' ' * whitespace))
            app.current = 0
            app.eport.clear()
            row+=1
        window.refresh()
        currentdata.clear()
        sniff_packets(interface)

if __name__ == '__main__':
    currentdata = []
    displaydata = []
    applist = []
    portrange = get_port_range()
    default = Application(name='<UNKNOWN>', current=0, total=0)
    displaydata.append(default)
    applist.append(displaydata[0].name)
    wrapper(main)
