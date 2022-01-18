'''

python3 wsmask.py -[mu] [-k 0xdeadbeef] -i input.bin -o output.bin

https://tools.ietf.org/html/rfc6455

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+

'''
import binascii
import sys
import random, string
import configparser
from configparser import NoSectionError
from argparse import ArgumentParser
from os.path import expanduser
from stat import *


class WebSocket():
    class OPMODE():
        MASK = 0x00
        UNMASK = 0x01

    class OPCODE():
        TXT = 0x01
        BIN = 0x02

    def mask(self, fdin, masking_key, opcode):
        payload_size = len(fdin)
        #print(f"payload size: {payload_size}")
        #print(f"maskingkey: {masking_key}")

        header = (0x80 | opcode).to_bytes(1, 'big')
        if payload_size <= 125:
            header += (payload_size | 0x80).to_bytes(1, 'big')
        elif payload_size <= 65535:
            header += (126 | 0x80).to_bytes(1, 'big')
            header += ((payload_size >> 8) & 0xff).to_bytes(1, 'big')
            header += (payload_size & 0xff).to_bytes(1, 'big')
        else:
            header += (127 | 0x80).to_bytes(1, 'big')
            header += ((payload_size >> 56) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 48) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 40) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 32) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 24) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 16) & 0xff).to_bytes(1, 'big')
            header += ((payload_size >> 8) & 0xff).to_bytes(1, 'big')
            header += (payload_size & 0xff).to_bytes(1, 'big')

        header += masking_key
        #print(header)

        payload = b''
        for i in range(payload_size):
            payload += (fdin[i] ^ masking_key[i%4]).to_bytes(1, 'big')

        return header+payload

    def unmask(self, fdin):
        file_size = len(fdin)
        #print(fdin)
        i = 0
        header = fdin[i]
        #print(header)
        i+=1
        if header != 0x81 and header != 0x82:
            print("wsmask: " + f"header[0]: {header} (!=0x81,0x82)")
            return b''

        masked = True
        header = fdin[i]
        i+=1
        if not header & 0x80:
            masked = False
            #print("not masked!")

        payload_size = header & 0x7f
        #print(payload_size)
        if payload_size <= 125:
            pass
        elif payload_size == 126:
            header = fdin[i:i+2]
            payload_size = fdin[i] << 8 | fdin[i+1]
            i+=2
        else:
            payload_size = fdin[i+0] << 56 | fdin[i+1] << 48 | fdin[i+2] << 40 | fdin[i+3] << 32 | fdin[i+4] << 24 | fdin[i+5] << 16 | fdin[i+6] << 8 | fdin[i+7];
            i+=8

        #print(f"payload size: {payload_size}")

        masking_key = b'\x00\x00\x00\x00'
        if masked:
            masking_key = fdin[i:i+4]
            i+=4

        #print(f"maskingkey: {masking_key}")

        payload = b''
        if payload_size <= len(fdin)-i:
          size = payload_size
        else:
          print("wsmask: insufficient payload size")
          size = len(fdin)-i

        for j in range(size):
            payload += (fdin[i+j] ^ masking_key[j%4]).to_bytes(1, 'big')

        return payload

def getArgs():
  usage = 'usage: python3 wsmask.py -t|b -m|u [-k xxxxxxxx] -i input.bin -o output.bin'
  argparser = ArgumentParser(usage=usage)
  argparser.add_argument('-t', '--text', action='store_false', dest='binary', help='use text mode')
  argparser.add_argument('-b', '--binary', action='store_true', dest='binary', help='use binary mode')
  argparser.add_argument('-m', '--mask', action='store_true', dest='mask', help='use text mode')
  argparser.add_argument('-u', '--unmask', action='store_false', dest='mask', help='use binary mode')
  argparser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='verbose')
  argparser.add_argument('-k', '--key', nargs='?', default='deadbeef', type=str, dest='key', help='key')
  argparser.add_argument('-i', '--infile', nargs='?', type=str, dest='infile', help='input file')
  argparser.add_argument('-o', '--outfile', nargs='?', type=str, dest='outfile', help='output file')
  return argparser.parse_args()

def main():
    args = getArgs()
    if not args.infile or not args.outfile:
      print("usage: python3 "+ __file__ + " -h")
      sys.exit(0)

    masking_key = None
    fdin = None
    fdout = None

    opmode = 0x01
    if args.mask:
        opmode = 0x00
    opcode = 0x01
    if args.binary:
        opcode = 0x02

    if len(args.key) == 8:
        masking_key = binascii.a2b_hex(args.key[0:2])
        masking_key += binascii.a2b_hex(args.key[2:4])
        masking_key += binascii.a2b_hex(args.key[4:6])
        masking_key += binascii.a2b_hex(args.key[6:8])
    else:
        masking_key = b'\xde\xad\xbe\xef'
    #print(f"{masking_key}")

    indata = None
    outdata = None
    with open(args.infile, "rb") as file:
        indata = file.read()

    if opmode == 0x00:
        print("masking mode")
        outdata = WebSocket().mask(indata, masking_key, opcode)
    else:
        print("unmasking mode")
        outdata = WebSocket().unmask(indata)

    with open(args.outfile, "wb") as file:
        file.write(outdata)

if __name__ == "__main__":
  main()
