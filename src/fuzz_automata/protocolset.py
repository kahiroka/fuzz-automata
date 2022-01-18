import json
from base64 import b64encode as b64e
from .protocol import Protocol

class ProtocolSet():
  def __init__(self, name='', comment=''):
    self.ps = {}
    self.ps['name'] = name
    self.ps['comment'] = comment
    self.ps['protocols'] = [] # protocol object list

  def append(self, protocol):
    self.ps['protocols'].append(protocol)

  def rebirth(self):
    for i in range(len(self.ps['protocols'])):
      p = Protocol()
      p.rebirth(self.ps['protocols'][i])
      self.ps['protocols'][i] = p

  def load(self, file):
    with open(file, 'r') as f:
      self.ps = json.load(f)
      self.rebirth()

  def save(self, file):
    with open(file, 'w') as f:
      json.dump(self.ps, f, indent=2)

  def merge_load(self, file):
    with open(file, 'r') as f:
      ps = json.load(f)
      if not self.ps['name']:
        self.ps['name'] = ps['name']
      if not self.ps['comment']:
        self.ps['comment'] = ps['comment']

      dst_proto_objs = self.ps['protocols']
      src_proto_dics = ps['protocols']

      for spdic in src_proto_dics:
        exist = False
        for dpobj in dst_proto_objs:
          if dpobj['dport'] == spdic['dport']:
            dpobj['payloads'].update(spdic['payloads'])
            exist = True
            break

        if not exist:
          p = Protocol()
          p.rebirth(spdic)
          dst_proto_objs.append(p)
    
  def minimize(self):
    for p in self.ps['protocols']:
      p.minimize()

    self.ps['protocols'] = [p for p in self.ps['protocols'] if len(p.get_payloads()) != 0]

  def get_ports(self):
    ports = {'tcp':[], 'udp':[]}
    for p in self.ps['protocols']:
      ports[p['proto']].append(p['dport'])

    return ports

  def get_protocols(self):
    return self.ps['protocols']

  def show(self):
    for p in self.ps['protocols']:
      p.show()

def main():
  p = Protocol('http', proto='tcp', dport='80')
  p.append(b64e(('GET / HTTP/1.1\r\n\r\n').encode('UTF-8')).decode())
  p.append(b64e(('POST / HTTP/1.1\r\n\r\n').encode('UTF-8')).decode())
  ps = ProtocolSet('sample target')
  ps.append(p)
  ps.save('sample.json')
  ps.merge_load('sample.json')
  ps.minimize()
  ps.save('sample_min.json')

if __name__ == '__main__':
  main()

