#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

import sys
from scapy.all import *

#http://www.win.tue.nl/~aeb/linux/kbd/scancodes-1.html#ss1.4
WIN32_KEYCODES = {'\x02':'1!','\x03':'2@','\x04':'3#','\x05':'4$','\x06':'5%','\x07':'6^','\x08':'7&','\x09':'8*','\x0a':'9(','\x0b':'0)',
'\x0c':'-_','\x0d':'=+','\x0e':'<BACKSPACE>','\x0f':'<TAB>','\x10':'q','\x11':'w','\x12':'e','\x13':'r','\x14':'t','\x15':'y','\x16':'u','\x17':'i',
'\x18':'o','\x19':'p','\x1a':'[{','\x1b':']}','\x1c':'<ENTER>','\x1d':'<LCTRL>','\x1e':'a','\x1f':'s','\x20':'d','\x21':'f','\x22':'g','\x23':'h','\x24':'j',
'\x25':'k','\x26':'l','\x27':';:','\x28':'\'"','\x29':'`~','\x2a':'LSHIFT>','\x2b':'\|','\x2c':'z','\x2d':'x','\x2e':'c','\x2f':'v','\x30':'b','\x31':'n',
'\x32':'m','\x33':',<','\x34':'.>','\x35':'/?','\x36':'<RSHIFT>','\x37':'<Keypad-*>','\x38':'<LALT>','\x39':'<SPACE>','\x3a':'<CAPS>','\x3b':'F1','\x3c':'F2',
'\x3d':'F3','\x3e':'F4','\x3f':'F5','\x40':'F6','\x41':'F7','\x42':'F8','\x43':'F9','\x44':'F10','\x45':'<NumLock>','\x46':'<SCROLLOCK>','\x47':'<Keypad-7/Home>',
'\x48':'<Keypad-8/Up>','\x49':'<Keypad-9/PgUp>','\x4a':'<Keypad-->','\x4b':'<Keypad-4/Left>','\x4c':'<Keypad-5>','\x4d':'<Keypad-6/Right>','\x4e':'<Keypad-+>','\x4f':'<Keypad-1/End>',
'\x50':'<Keypad-2/Down>','\x51':'<Keypad-3/PgDn>','\x52':'<Keypad-0/Ins>','\x53':'<Keypad-./Del>','\x54':'<Alt-SysRq>'}
      
def getkey(fullpacket):
    payload = str(fullpacket[Raw])
    if payload and payload[0:3] == '\x44\x04\x01':
        try:
            return WIN32_KEYCODES[payload[3]]
        except:
            return '<\\x' + payload[3].encode('hex') + '>'
    return ''         
      

if __name__ == "__main__":
    pcapdata = PcapReader(sys.argv[1])
    for packet in pcapdata:
        if packet.haslayer(TCP):
            sys.stdout.write(getkey(packet))
    print ''
