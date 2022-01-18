import pyradamsa
#from pyZZUF import *
from .wsmask import WebSocket
import msgpack
import json

# pip3 install pyradamsa
# pip3 install pyZZUF, btw python >=3.2 not suppoted

class Mutator():
  def  __init__(self, mutator='radamsa'):
    #self.radamsa = pyradamsa.Radamsa(seed=0) # this fixes seed at all trials
    self.radamsa = pyradamsa.Radamsa()
    #self.zzuf = pyZZUF(b'')
    self.mutator = mutator
    self.wsmask = WebSocket()

  def pack(self, input, stack):
    if stack == 'wsbin' or stack == 'wstxt':
      opmode = 0x01 if stack == 'wstxt' else 0x02
      input = self.wsmask.mask(input, b'\x00\x00\x00\x00', opmode)

    elif stack == 'msgpack': # txt->obj->msgpack
      try:
        input = json.loads(input.decode())
      except json.decoder.JSONDecodeError:
        return b''
      except UnicodeDecodeError:
        return b''

      try:
        input = msgpack.packb(input)
      except msgpack.exceptions.PackOverflowError:
        input = b''

    else:
      print("pack: unknown stack")

    return input

  def unpack(self, input, stack):
    if stack == 'wsbin' or stack == 'wstxt':
      input = self.wsmask.unmask(input)

    elif stack == 'msgpack': # msgpack->obj->txt
      try:
        input = str(msgpack.unpackb(input)) # need to fix json format
        input = input.replace(", b'", ", \"").replace(": b'", ": \"")
        input = input.replace("{b'", "{\"").replace("[b'", "[\"")
        input = input.replace("', ", "\",").replace("':", "\":")
        input = input.replace("'}", "\"}").replace("']", "\"]")
        input = bytes(input, 'UTF-8')
      except msgpack.exceptions.UnpackValueError:
        input = b''

    else:
      print("unpack: unknown stack")

    return input

  def mutate(self, input, stack=[]):
    orig = input

    for s in stack:
      orig = self.unpack(orig, s)
      if orig == b'':
        stack = []
        orig = input
        break

    for i in range(10): # retry count
      success = True
      if self.mutator == 'radamsa':
        tmp = self.radamsa.fuzz(orig)
      #elif self.mutator == 'zzuf':
      #  self.zzuf.set_buffer(input)
      #  self.zzuf.set_ratio(0.04)
      #  return self.zzuf.mutate().tobytes()

      for s in reversed(stack):
        tmp = self.pack(tmp, s)
        if tmp == b'':
          success = False

      if success:
        break

    if success:
      return tmp
    else:
      return input

def main():
  print("radamsa test:")
  m = Mutator('radamsa')
  for i in range(5):
    print(m.mutate(b'Hello'))

  #print("zzuf test:")
  #m = Mutator('zzuf')
  #for i in range(5):
  #  print(m.mutate(b'Hello'))

if __name__ == '__main__':
  main()

