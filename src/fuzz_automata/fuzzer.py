import sys
import random
from pwn import *
from .protocolset import ProtocolSet
from .fanmap import FaNmap
from .mutator import Mutator
from .logger import Logger
from multiprocessing import Process

class Fuzzer():
  def __init__(self, file):
    self.ps = ProtocolSet()
    self.ps.load(file)
    self.mutator = Mutator('radamsa')
    self.proc_list = []

  def _fuzz_oneshot(self, logger, ip, port, proto, stack, payloads):
    print("# oneshot mode")
    for payload in payloads:
      io = remote(ip, port, typ=proto)
      logger.log({'cmd':'con', 'ip':ip, 'port':port, 'proto':proto})
      fuzz = self.mutator.mutate(b64d(payload.encode()), stack)
      io.send(fuzz)
      logger.log({'cmd':'fuz', 'data':b64e(fuzz)})
      try:
        ret = io.recvrepeat(0.2)
      except EOFError:
        pass
      finally:
        io.close()
        logger.log({'cmd':'dis'})

  def _fuzz_sequence(self, logger, ip, port, proto, stack, payloads, pileup, stir):
    print("# sequence mode")
    # augmentation option
    for i in range(int(pileup)):
      payloads.extend(payloads)
    if pileup > 0:
      print("pileup: 2^" + str(pileup))
    print(len(payloads))

    io = remote(ip, port, typ=proto)
    logger.log({'cmd':'con', 'ip':ip, 'port':port, 'proto':proto})

    lut = list(range(len(payloads)))
    if stir and len(lut)>3:
      lut[1:-1] = random.sample(lut[1:-1], len(lut[1:-1]))

    # heuristic: shallow-deep fuzzing
    for i in range(len(payloads)):
      for j in range(len(payloads)):
        if j < i:
          fuzz = b64d(payloads[lut[j]].encode())
        else:
          fuzz = self.mutator.mutate(b64d(payloads[lut[j]].encode()), stack)

        try:
          io.send(fuzz)
          logger.log({'cmd':'fuz', 'data':b64e(fuzz)})
          ret = io.recvrepeat(0.2)
        except EOFError:
          #print("EOFError")
          break

    io.close()
    logger.log({'cmd':'dis'})

  def run_mp(self, p, ip, pileup, stir):
    dport = p.get_dport()
    proto = p.get_proto()
    typ = p.get_type()
    stack = p.get_stack()
    print(dport + "/" + proto)
    payloads = p.get_payloads()
    logger = Logger(dport + '-' + proto)
    logger.enable()

    while True:
      for sport in payloads:
        if typ == 'oneshots':
          for i in range(10):
            self._fuzz_oneshot(logger, ip, dport, proto, stack, payloads[sport])
        elif typ == 'sequence':
          self._fuzz_sequence(logger, ip, dport, proto, stack, payloads[sport], pileup, stir)

  def run(self, ip, port=None, proto=None, pileup=0, stir=False):
    print("Protocol Set: " + str(self.ps.get_ports()))
    if port == None:
      fn = FaNmap()
      active_ports = fn.nmap(ip, self.ps.get_ports())
      print("Active Ports: " + str(active_ports))
      if len(active_ports) == 0:
        print("no target port")
        return
    else:
      active_ports = {'tcp':[], 'udp':[]}
      if proto == None:
        active_ports['tcp'].append(port)
        active_ports['udp'].append(port)
      else:
        active_ports[proto].append(port)

    for p in self.ps.get_protocols():
      dport = p.get_dport()
      proto = p.get_proto()
      if dport in active_ports[proto]:
        proc = Process(target=self.run_mp, args=(p, ip, pileup, stir))
        proc.start()
        self.proc_list.append(proc)

    for proc in self.proc_list:
      proc.join()

def main():
  if len(sys.argv) == 3:
    seed_file = sys.argv[1]
    target_ip = sys.argv[2]

    fuzzer = Fuzzer(seed_file)
    try:
      fuzzer.run(target_ip)
    except KeyboardInterrupt:
      print("interrupted")
  else:
    print("python3 ./fuzzer.py seed_file target_ip")

if __name__ == '__main__':
  main()
