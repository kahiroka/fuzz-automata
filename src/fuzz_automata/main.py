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
from .portablescript import PortableScript

def getArgs():
  usage = '''
fuzz-automata -pcap in.pcap -out seeds.json -ip x.x.x.x [-multicast]
fuzz-automata -out seeds.json [-minimize] -merge seeds1.json [seeds2.json ...]
fuzz-automata -fuzz seeds.json -ip x.x.x.x [-port #] [-proto tcp|udp] [-pileup #] [-proxy ip:port]
fuzz-automata -replay fuzz.log -ip x.x.x.x [-binsearch]
fuzz-automata -log2sh fuzz.log -out poc.sh
fuzz-automata -log2seeds fuzz.log -out seeds.json
fuzz-automata -show seeds.json
'''
  
  argparser = ArgumentParser(usage=usage)
  argparser.add_argument('-pcap', nargs='?', type=str, dest='pcap', help='input pcap file')
  argparser.add_argument('-out', nargs='?', type=str, dest='out', help='output file')
  argparser.add_argument('-merge', nargs='+', type=str, dest='merge', help='merge seeds json files')
  argparser.add_argument('-minimize', action='store_true', dest='minimize', help='minimize payloads (optional)')
  argparser.add_argument('-log2sh', nargs='?', type=str, dest='log2sh', help='generate a portable shell script from the log file')
  argparser.add_argument('-log2seeds', nargs='?', type=str, dest='log2seeds', help='restore from the log file to a seeds json file')
  argparser.add_argument('-seeds2sh', nargs='?', type=str, dest='seeds2sh', help='generate a portable shell script from a seeds json file')
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
  argparser.add_argument('-stir', action='store_true', dest='stir', help='stir sequential packets (optional)')

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
    pss = PortableScript()
    pss.export_log(args.log2sh, args.out)

  elif args.seeds2sh and args.out:
    pss = PortableScript()
    pss.export_seeds(args.seeds2sh, args.out)

  elif args.log2seeds and args.out:
    logger = Logger()
    logger.restore(args.log2seeds, args.out)

  elif args.fuzz and args.ip and args.proxy:
    proxy = Proxy(args.fuzz, args.ip, args.proxy)
    try:
      proxy.run()
    except KeyboardInterrupt:
      print("interrupted")

  elif args.fuzz and args.ip:
    fuzzer = Fuzzer(args.fuzz)
    try:
      fuzzer.run(ip=args.ip, port=args.port, proto=args.proto, pileup=args.pileup, stir=args.stir)
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
