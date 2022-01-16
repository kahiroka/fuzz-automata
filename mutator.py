import pyradamsa
#from pyZZUF import *

# pip3 install pyradamsa
# pip3 install pyZZUF, btw python >=3.2 not suppoted

class Mutator():
  def  __init__(self, mutator='radamsa'):
    #self.radamsa = pyradamsa.Radamsa(seed=0) # this fixes seed at all trials
    self.radamsa = pyradamsa.Radamsa()
    #self.zzuf = pyZZUF(b'')
    self.mutator = mutator

  def mutate(self, input, stack=[]):
    if self.mutator == 'radamsa':
      return self.radamsa.fuzz(input)
    #elif self.mutator == 'zzuf':
    #  self.zzuf.set_buffer(input)
    #  self.zzuf.set_ratio(0.04)
    #  return self.zzuf.mutate().tobytes()

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

