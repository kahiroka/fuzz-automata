#!/usr/bin/env python3
'''
FuzZ:Automata: Seed-based Random Network Fuzzer
'''
from argparse import ArgumentParser
from pwn import *
from .protocolset import ProtocolSet
from .protocolextractor import ProtocolExtractor
from .logger import Logger
from .fuzzer import Fuzzer
from .player import Player
from .proxy import Proxy

def getArgs():
  usage = '''
python3 fuzz-automata.py -pcap in.pcap -out seeds.json -ip x.x.x.x [-multicast]
python3 fuzz-automata.py -out out.json [-minimize] -merge seeds1.json [seeds2.json ...]
python3 fuzz-automata.py -fuzz seeds.json -ip x.x.x.x [-port #] [-proto tcp|udp] [-pileup #] [-proxy ip:port]
python3 fuzz-automata.py -replay fuzz.log -ip x.x.x.x [-binsearch]
python3 fuzz-automata.py -log2sh fuzz.log -out poc.sh
python3 fuzz-automata.py -show seeds.json
'''
  
  argparser = ArgumentParser(usage=usage)
  argparser.add_argument('-pcap', nargs='?', type=str, dest='pcap', help='input pcap file')
  argparser.add_argument('-out', nargs='?', type=str, dest='out', help='output file')
  argparser.add_argument('-merge', nargs='+', type=str, dest='merge', help='merge seeds json files')
  argparser.add_argument('-minimize', action='store_true', dest='minimize', help='minimize payloads (optional)')
  argparser.add_argument('-log2sh', nargs='?', type=str, dest='log2sh', help='generate a portable shell script from the log file')
  argparser.add_argument('-fuzz', nargs='?', type=str, dest='fuzz', help='input seeds json file')
  argparser.add_argument('-ip', nargs='?', type=str, dest='ip', help='target ip address')
  argparser.add_argument('-port', nargs='?', default=None, type=str, dest='port', help='limit to the port number (optional)')
  argparser.add_argument('-proto', nargs='?', default=None, type=str, dest='proto', help='limit to the protocol: tcp|udp (optional)')
  argparser.add_argument('-pileup', nargs='?', default=0, type=int, dest='pileup', help='pile up payloads (optional)')
  argparser.add_argument('-replay', nargs='?', type=str, dest='replay', help='replay the log to a specified ip address')
  argparser.add_argument('-proxy', nargs='?', type=str, dest='proxy', help='pass http requests in a seeds file to the specified proxy for fuzzing (optional)')
  argparser.add_argument('-binsearch', action='store_true', dest='binsearch', help='binary search for packets that cause a target to halt (optional)')
  argparser.add_argument('-multicast', action='store_true', dest='multicast', help='include ip multicast packets from others (optional)')
  argparser.add_argument('-show', nargs='?', type=str, dest='show', help='show packet info of a json file')

  return argparser.parse_args()

def main():
  args = getArgs()

  if args.pcap and args.out and args.ip:
    try:
      pe = ProtocolExtractor(args.pcap, args.ip, args.multicast)
      pe.save(args.out)
    except FileNotFoundError:
      print("pcap file not found")

  elif args.merge and args.out:
    ps = ProtocolSet()
    for file in args.merge:
      ps.merge_load(file)
    if args.minimize:
      ps.minimize()
    ps.save(args.out)

  elif args.log2sh and args.out:
    logger = Logger()
    logger.export(args.log2sh, args.out)

  elif args.fuzz and args.ip and args.proxy:
    proxy = Proxy(args.fuzz, args.ip, args.proxy)
    try:
      proxy.run()
    except KeyboardInterrupt:
      print("interrupted")

  elif args.fuzz and args.ip:
    fuzzer = Fuzzer(args.fuzz)
    try:
      fuzzer.run(ip=args.ip, port=args.port, proto=args.proto, pileup=args.pileup)
    except KeyboardInterrupt:
      print("interrupted")

  elif args.replay and args.ip:
    player = Player(args.replay, args.ip)
    try:
      player.run(args.binsearch)
    except KeyboardInterrupt:
      print("interrupted")

  elif args.show:
    ps = ProtocolSet()
    ps.load(args.show)
    ps.show()

  else:
    print("usage: python3 "+ __file__ + " -h")

if __name__ == '__main__':
  main()
