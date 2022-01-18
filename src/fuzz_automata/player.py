from pwn import *
import sys
from .logger import Logger

class Player():
  def __init__(self, logfile, ip=None):
    self.ip = ip
    self.logger = Logger()
    self.logger.load(logfile)
    self.start = 0
    self.size = 0

  def _run_normal(self):
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

  def _run_binsearch(self, start, size):
    print("# " + str(start) + ", " + str(start+size-1))
    self.logger.seek(start)
    for i in range(size):
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
          break

    size1 = int(size/2)
    size2 = size - size1
    start1 = start
    start2 = start + size1

    res = input("target stuck? (y/n): ")
    if res.startswith('y'):
      self.start = start
      self.size = size

      if size == 1:
        return True

      if self._run_binsearch(start1, size1):
        return True
      else:
        self._run_binsearch(start2, size2)
        return True
    else:
      return False

  def run(self, binsearch=False):
    if binsearch:
      self._run_binsearch(0, self.logger.get_len())
      self.logger.cut_out(self.start, self.size)
    else:
      self._run_normal()

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
