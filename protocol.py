from base64 import b64encode as b64e
from base64 import b64decode as b64d

class Protocol(dict):
  def __init__(self, name='', proto='tcp', dport='0', type='oneshots', mcast=False):
    self.proto = {}
    self.proto['name'] = name
    self.proto['proto'] = proto
    self.proto['dport'] = dport
    self.proto['type'] = type # oneshots or sequence
    self.proto['mcast'] = mcast
    self.proto['stack'] = []
    self.proto['payloads'] = {} # {src_port_num:[payload1, payload2, ...], }
    dict.__init__(self, self.proto)

  def append(self, payload, sport='0', concat=False):
    if not sport in self.proto['payloads']:
      self.proto['payloads'][sport] = []

    if concat:
      prev = self.proto['payloads'][sport][-1]
      merged = b64e(b64d(prev) + b64d(payload)).decode()
      self.proto['payloads'][sport][-1] = merged
    else:
      self.proto['payloads'][sport].append(payload)
    self.update_type()

  # heuristic: just remove same size payloads
  def minimize(self):
    id = {}
    if not self.proto['dport'] in id:
      id[self.proto['dport']] = []

    for sport in dict(self.proto['payloads']):
      for payload in list(self.proto['payloads'][sport]):
        if not len(payload) in id[self.proto['dport']] and 4096 >= len(payload):
          id[self.proto['dport']].append(len(payload))
        else:
          self.proto['payloads'][sport].remove(payload)
          if len(self.proto['payloads'][sport]) == 0: # no payload
            self.proto['payloads'].pop(sport)

    self.update_type()

  def update_type(self):
    total = len(self.proto['payloads'])
    count = 0
    for p in self.proto['payloads']:
      if len(self.proto['payloads'][p]) > 1:
        count = count + 1
    if count < total/2:
      self.proto['type'] = 'oneshots'
    else:
      self.proto['type'] = 'sequence'

    dict.__init__(self, self.proto)

  def show(self):
    print(self.proto['name'])
    print("  proto: " + self.proto['proto'] + "/" + self.proto['dport'])
    print("  type : " + self.proto['type'] + ", mcast: " + str(self.proto['mcast']))
    count = 0
    sumsz = 0
    for sport in self.proto['payloads']:
      count = count + len(self.proto['payloads'][sport])
      for payload in self.proto['payloads'][sport]:
        sumsz = sumsz + len(b64d(payload))
    print("  avg# : " + str(int(sumsz/count)) + " bytes x" + str(count))

  def get_proto(self):
    return self.proto['proto']

  def get_dport(self):
    return self.proto['dport']

  def get_type(self):
    return self.proto['type']

  def get_stack(self):
    return self.proto['stack']

  def get_payloads(self):
    return self.proto['payloads']

  def rebirth(self, proto):
    self.proto = proto
    dict.__init__(self, self.proto)

  def __getitem__(self, key):
    return self.proto[key]

  def __repr__(self):
    return repr(self.proto)

def main():
  proto = Protocol('proto')
  proto.append('BASE64ed')

if __name__ == '__main__':
  main()

