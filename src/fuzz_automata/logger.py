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
LOADER='''(while read line;do echo -n $line|base64 -d;$WAIT;done<<EOF
'''
FOOTER='''EOF
)|$NC '''

class Logger():
  def __init__(self, name='0'):
    self.logfile = None
    self.logfp  = None
    self.repfile = None
    self.repfp  = None
    self.enabled = False
    self.name = name
    self.index = []

  def enable(self):
    if not self.enabled:
      self.logfile = datetime.datetime.today().strftime('%Y%m%d-%H%M%S') + '-' + self.name + '.log'
      self.logfp = open(self.logfile, 'w')
      self.enabled = True

  def disable(self):
    if self.enabled:
      self.logfp.close()
      self.enabled = False

  # {'cmd':'con', 'ip':'192.168.0.1', 'port:'8080', 'proto':'tcp'}
  def log(self, data):
    if self.enabled:
      self.logfp.write(json.dumps(data) + '\n')
      self.logfp.flush()

  def get_filename(self):
    return self.logfile

  def load(self, repfile):
    self.repfile = repfile
    self.repfp = open(self.repfile, 'r')

    pos = 0
    #for line in self.repfp:
    while True:
      line = self.repfp.readline()
      if not line:
        break
      log = json.loads(line)
      if log['cmd'] == 'con':
        self.index.append(pos)
      elif log['cmd'] == 'dis':
        pass

      pos = self.repfp.tell()

    self.index.append(pos)
    self.repfp.seek(0)

  def next(self):
    for line in self.repfp:
      if line[0] == '#':
        continue
      log = json.loads(line)
      return log

  def get_len(self):
    return len(self.index) - 1

  def seek(self, pos):
    if pos < len(self.index) - 1:
      self.repfp.seek(self.index[pos])
      return self.index[pos]
    else:
      return -1

  def cut_out(self, start, size):
    self.seek(start)
    with open(self.repfile + '.poc', 'w') as fw:
      left = self.index[start+size] - self.index[start]
      while left:
        data = self.repfp.read(left)
        fw.write(data)
        left = left - len(data)

  def restore(self, logfile, outfile):
    with open(logfile, 'r') as fr:
      ps = ProtocolSet(name='unknown')
      protocols = {}
      sport = 0
      for line in fr:
        if line[0] == '#':
          continue

        log = json.loads(line)
        if log['cmd'] == 'con':
          ip = log['ip']
          dport = log['port']
          proto = log['proto']
          if not dport in protocols:
            protocols[dport] = Protocol(name='unknown', proto=proto, dport=dport, type='sequence')
        elif log['cmd'] == 'dis':
          sport = sport + 1
        elif log['cmd'] == 'fuz':
          protocols[dport].append(log['data'], sport=str(sport))
        else:
          print("unknown cmd")

      for dport in protocols:
        ps.append(protocols[dport])
      ps.save(outfile)

def main():
  l = Logger()
  l.enable()
  l.log({'cmd':'con', 'ip':'192.168.0.1', 'port':'80', 'proto':'tcp'})
  l.log({'cmd':'fuz', 'data':'R0VUIC8gSFRUUC8xLjENCg0K'})
  l.log({'cmd':'fuz', 'data':'R0VUIC8gSFRUUC8xLjENCg0K'})
  l.log({'cmd':'dis'})
  l.log({'cmd':'con', 'ip':'192.168.0.1', 'port':'80', 'proto':'tcp'})
  l.log({'cmd':'fuz', 'data':'R0VUIC8gSFRUUC8xLjENCg0K'})
  l.log({'cmd':'dis'})
  l.disable()
  l.export(l.get_filename(), 'expoted.sh')

if __name__ == '__main__':
  main()
