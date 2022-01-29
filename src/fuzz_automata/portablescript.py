import json
import datetime
from pwn import *
from .protocol import Protocol
from .protocolset import ProtocolSet

HEADER='''#!/bin/sh
if [ $# != 1 ]; then
  echo usage: ./portable-poc-template.sh IPADDRESS
  exit
fi
IP=$1
PORT=
#UDP="-u"
WAIT="sleep 0.1"
NC="nc -q 1 -w 1 $UDP $IP $PORT"
'''
LOADER_PLAY='''(while read line;do echo -n $line|base64 -d;$WAIT;done<<EOF
'''
LOADER_FUZZ='''(while read line;do echo -n $line|base64 -d|radamsa;$WAIT;done<<EOF
'''
FOOTER='''EOF
)|$NC '''

class PortableScript():
  def __init__(self, name='0'):
    pass

  def export_log(self, logfile, outfile):
    port = '0'
    with open(logfile, 'r') as fr:
      with open(outfile, 'w') as fw:
        fw.write(HEADER)
        for line in fr:
          if line[0] == '#':
            continue

          log = json.loads(line)
          if log['cmd'] == 'con':
            fw.write(LOADER_PLAY)
            port = log['port']
          elif log['cmd'] == 'dis':
            fw.write(FOOTER)
            fw.write(port + '\n')
          elif log['cmd'] == 'fuz':
            fw.write(log['data']+'\n')
          else:
            print("unknown cmd")

  def export_seeds(self, seedsfile, outfile):
    ps = ProtocolSet()
    ps.load(seedsfile)
    for p in ps.get_protocols():
      if p['type'] == 'oneshots':
        with open(outfile+'.'+p['dport'], 'w') as fw:
          fw.write(HEADER)
          fw.write('while true; do\n')
          for sport in p['payloads']:
            for payload in p['payloads'][sport]:
              fw.write(LOADER_FUZZ)
              fw.write(payload + '\n')
              fw.write(FOOTER)
              fw.write(p['dport'] + '\n')
          fw.write('done\n')
      elif p['type'] == 'sequence':
        with open(outfile+'.'+p['dport'], 'w') as fw:
          fw.write(HEADER)
          fw.write('while true; do\n')
          for sport in p['payloads']:
            fw.write(LOADER_FUZZ)
            for payload in p['payloads'][sport]:
              fw.write(payload + '\n')
            fw.write(FOOTER)
            fw.write(p['dport'] + '\n')
          fw.write('done\n')
      else:
        print("unknown type")

def main():
  l = Logger()
  l.export_log('fuzz.log', 'poc.sh')
  l.export_seeds('seeds.json', 'fuzz.sh')

if __name__ == '__main__':
  main()
