#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField, PacketListField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from scapy.all import bind_layers

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

######################Essa classe era demo
#class IPOption_MRI(IPOption):
#    name = "MRI"
#    option = 31
#    fields_desc = [ _IPOption_HDR,
#                    FieldLenField("length", None, fmt="B",
#                                  length_of="swids",
#                                  adjust=lambda pkt,l:l+4),
#                    ShortField("count", 0),
#                    FieldListField("swids",
#                                   [],
#                                   IntField("", 0),
#                                   length_from=lambda pkt:pkt.count*4) ]
#
#####################################################
class INT_Filho(Packet):
    name = "INF Filho"
    fields_desc = [  IntField("ID_Switch",0),
                     BitField("Porta_Entrada",0, 9),
                     BitField("Porta_Saida",0, 9),
                     BitField("TimeStamp",0, 48),
                     BitField("Padding",0, 6),
                    ]
    def extract_padding(self, p):
        return "", p   #especifica zero padding. Nessesario caso underlayer nao especifica o length do payload


#Nossa classe
class INT(Packet):
    name = "INT packet"

    fields_desc=[ IntField("Tamanho_Filho",0),
                  IntField("Quantidade_Filhos", None),
                  ByteField("next_header", 6),
                  PacketListField("plist", None, INT_Filho, count_from= lambda pkt:pkt.Quantidade_Filhos)]
                  #PacketListField("plist", None, INT_Filho, length_from= lambda pkt: pkt.Quantidade_Filhos*pkt.Tamanho_Filho) ]

#    def extract_padding(self, p):
#        return "", p


#####################################################


#funcao chamada a cada pacote que chega
def handle_pkt(pkt):
    
    #if IP in pkt and pkt[IP].proto == 150:
    if INT in pkt and pkt[INT].next_header!= 1:
#        print "got a packet"
        pkt.show2()
#    if TCP in pkt and pkt[TCP].dport == 1234:
#        print "got a packet"
#    #    hexdump(pkt)
    sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()

    #Adiciona o INT na stack, apos o parser do IP.
    bind_layers(IP, INT, proto=150)
    bind_layers(INT, TCP, next_header= 0x06)
    bind_layers(INT, UDP, next_header= 0x11)

    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
