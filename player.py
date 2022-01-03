from pwn import *
import sys
from logger import Logger

class Player():
  def __init__(self, logfile, ip=None):
    self.ip = ip
    self.logger = Logger()
    self.logger.load(logfile)

  def run(self):
    while True:
      log = self.logger.next()
      if log == None or not 'cmd' in log:
        break

      if log['cmd'] == 'con':
        if self.ip == None:
          io = remote(log['ip'], log['port'], typ=log['proto'])
        else:
          io = remote(self.ip, log['port'], typ=log['proto'])
      elif log['cmd'] == 'fuz':
        io.send(b64d(log['data'].encode()))
        try:
          ret = io.recvrepeat(0.2)
        except EOFError:
           pass
      elif log['cmd'] == 'dis':
        io.close()

def main():
  if len(sys.argv) == 3:
    log_file = sys.argv[1]
    target_ip = sys.argv[2]
    
    player = Player(log_file, target_ip)
    try:
      player.run()
    except KeyboardInterrupt:
      print("interrupted")
  else:
    print("python3 ./player.py log_file target_ip")

if __name__ == '__main__':
  main()
