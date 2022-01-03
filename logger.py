import json
import datetime
from pwn import *

HEADER='''#!/bin/sh
if [ $# != 1 ]; then
  echo usage: ./portable-poc-template.sh IPADDRESS
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
  def __init__(self):
    self.logfile = None
    self.logfp  = None
    self.repfile = None
    self.logfp  = None
    self.enabled = False

  def enable(self):
    if not self.enabled:
      self.logfile = datetime.datetime.today().strftime('%Y%m%d-%H%M%S') + '.log'
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

  def next(self):
    for line in self.repfp:
      if line[0] == '#':
        continue
      j = json.loads(line)
      return j

  def seek(self, pos):
    self.repfp.seek(pos)

  def export(self, logfile, outfile):
    port = '0'
    with open(logfile, 'r') as fr:
      with open(outfile, 'w') as fw:
        fw.write(HEADER)
        for line in fr:
          if line[0] == '#':
            continue

          log = json.loads(line)
          if log['cmd'] == 'con':
            fw.write(LOADER)
            port = log['port']
          elif log['cmd'] == 'dis':
            fw.write(FOOTER)
            fw.write( port + '\n')
          elif log['cmd'] == 'fuz':
            fw.write(log['data']+'\n')
          else:
            print("unknown cmd")

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
