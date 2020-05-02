
from scapy.all import *
import sys, os

TYPE_MYTUNNEL = 0x1212
TYPE_IPV4 = 0x0800

class Status(Packet):
    name = "Status"
    fields_desc = [
        ShortField("pid", 0),
        ShortField("T", 0)
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, T=%T%")


bind_layers(Ether, Status, type=TYPE_STATUSTAG)
bind_layers(Status, IP, pid=TYPE_IPV4)

