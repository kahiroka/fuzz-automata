class Protocol(dict):
  def __init__(self, name='', proto='tcp', dport='0', type='oneshots'):
    self.proto = {}
    self.proto['name'] = name
    self.proto['proto'] = proto
    self.proto['dport'] = dport
    self.proto['type'] = type # oneshots or sequence
    self.proto['payloads'] = {} # {src_port_num:[payload1, payload2, ...], }
    dict.__init__(self, self.proto)

  def append(self, payload, sport='0'):
    if not sport in self.proto['payloads']:
      self.proto['payloads'][sport] = []

    self.proto['payloads'][sport].append(payload)
    self.update_type()

  # heuristic: just remove same size payloads
  def minimize(self):
    id = {}
    if not self.proto['dport'] in id:
      id[self.proto['dport']] = []

    for sport in dict(self.proto['payloads']):
      for payload in list(self.proto['payloads'][sport]):
        if not len(payload) in id[self.proto['dport']]:
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

  def get_proto(self):
    return self.proto['proto']

  def get_dport(self):
    return self.proto['dport']

  def get_type(self):
    return self.proto['type']

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
