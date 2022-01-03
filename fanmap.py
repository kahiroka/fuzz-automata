import sys
import nmap

class FaNmap():
  def nmap(self, ip, spec_ports):
    scanner = nmap.PortScanner()
    portopt = self.from_dict(spec_ports)
    result = scanner.scan(ip, portopt, '') # '-sU' option requires root priv

    active_ports = {'tcp':[], 'udp':[]}
    if ip in result['scan']:
      if 'tcp' in scanner[ip]:
        for port in scanner[ip]['tcp']:
          if scanner[ip]['tcp'][port]['state'] == 'open':
            active_ports['tcp'].append(str(port))

      #if 'udp' in ps[ip]:
      #  for port in ps[ip]['udp']:
      #    if ps[ip]['udp'][port]['state'] == 'open|filterd':
      #      active_ports['udp'].append(str(port))

    return active_ports

  def to_dict(self, portopt):
    dict = {'tcp':[], 'udp':[]}
    port_list = portopt.replace(':', ',').split(',')

    proto = None
    for port in port_list:
      if port == 'T':
        proto = 'tcp'
      elif port == 'U':
        proto = 'udp'
      else:
        if proto == None:
          dict['tcp'].append(port)
          dict['udp'].append(port)
        else:
          dict[proto].append(port)

    return dict

  def from_dict(self, dict):
    portopt = ''

    if len(dict['tcp']) > 0:
      portopt = portopt + 'T:'
    for p in dict['tcp']:
      portopt = portopt + p + ','

    if len(dict['udp']) > 0:
      portopt = portopt + 'U:'
    for p in dict['tcp']:
      portopt = portopt + p + ','

    return portopt[:-1]

def main():
  if len(sys.argv) == 3:
    target_ip = sys.argv[1]
    spec_ports = sys.argv[2] # T:80,8080,U:80

    try:
      active_ports = FaNmap().nmap(target_ip, FaNmap().to_dict(spec_ports))
      print(active_ports)
    except KeyboardInterrupt:
      print("interrupted")
  else:
    print("python3 ./fanmap.py target_ip ports")

if __name__ == '__main__':
  main()
