from subprocess import *
import socket
import sys
import platform

set_ip = None
interface = None

def set_local_ip(cl_ip):
  assert socket.inet_aton(cl_ip)
  global set_ip 
  set_ip = cl_ip

def set_interface(iface):
  global interface 
  # XXX check this is a valid interface?
  interface = iface

def get_interface():
  os_type = platform.system()
  global interface
  if interface:
    return interface
  if os_type == "Linux":
    interface = get_linux_interface()
  elif os_type == 'Darwin':
    interface = get_darwin_interface()
  elif os_type == 'Windows':
    interface = get_windows_interface()
  elif os_type[-3:] == "BSD":
    interface = get_bsd_interface()
  else:
    raise OSError, "Don't know how to identify the network interface used to reach the Internet.  Try specifying one with -i <interface>"
  if not interface:
    print 'sorry, couldn''t detect your network interface (is it up?)\n'
    print 'please use -i to specify an interface\n'
    sys.exit(1)
  assert interface
  return interface
 


def get_local_ip():
  """ 
  Figure out the local IP address, by hook or by crook.  Optional
  command line hints about the local IP should be passed in here; sometimes
  we might need them.  
  """

  os_type = platform.system()
  if set_ip != None:
    # Maybe we'll want to double check this in the future
    socket.inet_aton(set_ip)
    return set_ip
  if os_type == "Linux":
    interface = get_linux_interface()
    if interface != None:
      ip=get_linux_local_ip(interface)
      return ip
  elif os_type == 'Darwin':
    interface = get_darwin_interface()
    if interface != None:
      ip=get_darwin_local_ip(interface)
      return ip
  elif os_type == 'Windows':
    return get_windows_local_ip()
  elif os_type[-3:] == "BSD":
    interface = get_bsd_interface()
    if interface != None:
      ip=get_darwin_local_ip(interface)
      return ip
  else:
    print "Alice cannot id your local IP address. Check that you have \
network access;  if you do, try adding your LAN IP manually with -l"
    sys.exit(0)

  print "Alice could not id your network interface. Check that you have \
network access;  if you do, try adding the local interface manually with -i"
  sys.exit(0)


# XXX Audit for local privilege escalation here

def get_linux_interface():
  "Guess which interface we are using, on linux"

  cmd = Popen(["/sbin/route", "-n"], stdout=PIPE, stderr=PIPE)
  ret = cmd.wait()

  if ret != 0:
    cmd = Popen(["route", "-n"], stdout=PIPE, stderr=PIPE)
    ret = cmd.wait()

  if ret !=0:
    return -1

  for line in cmd.stdout.readlines():
    words = line.split()
    try:
      # This is the default route
      if words[0] == "0.0.0.0":
        return words[-1]
    except IndexError:
      pass

  return None

def get_darwin_interface():
  "Guess which interface we are using, on darwin"

  cmd = Popen(["/sbin/route", "-n", "get", "default"], stdout=PIPE, stderr=PIPE)
  ret = cmd.wait()

  if ret != 0:
    cmd = Popen(["route", "-n", "get", "default"], stdout=PIPE, stderr=PIPE)
    ret = cmd.wait()

  if ret !=0:
    return -1

  for line in cmd.stdout.readlines():
    words = line.split()
    try:
      # This is the default route
      if words[0] == "interface:":
        return words[-1]
    except IndexError:
      pass

  return None

def get_windows_connection_names():
  """ return a map from pretty connection name -> interface device guid """
  import _winreg as r
  k = r.OpenKey(r.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}')
  (nsk, blah, blah) = r.QueryInfoKey(k)
  connections = {}
  for i in xrange(0,nsk):
    dev = r.EnumKey(k,i)
    if len(dev) == 38 and dev[0]=='{': # guid
      try:
        sk = r.OpenKey(k, dev+'\Connection')
        name = r.QueryValueEx(sk, 'Name')
        connections[name[0]] = dev
      except:
        pass

  return connections

def get_windows_interface():
  """ get device name of default interface """
  # 1. get ip address of default route
  ip = get_windows_local_ip()
  if ip == -1:
    return None

  # 2. get network device keys from registry
  devices = get_windows_connection_names().values()

  # 3. scan registry to figure out which has ip
  import _winreg as r
  for dev in devices:
    try:
      kn = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"+dev
      k = r.OpenKey(r.HKEY_LOCAL_MACHINE, kn)
      enable_dhcp = r.QueryValueEx(k, 'EnableDHCP')[0]
      if enable_dhcp:
        dhcp_ip = r.QueryValueEx(k, 'DhcpIPAddress')[0]
        if dhcp_ip == ip:
            return "\\Device\\NPF_"+dev
      else:
        static_ip = r.QueryValueEx(k, 'IPAddress')[0][0]
        if static_ip == ip:
            return "\\Device\\NPF_"+dev
    except:
      pass

  return None

def get_darwin_local_ip(interface):
  cmd = Popen(["/sbin/ifconfig", interface], stdout=PIPE, stderr=PIPE)
  ret = cmd.wait()
  if ret !=0:
    print cmd.stderr.read()
    return -1
  words = cmd.stdout.read().split()
  num_words = len(words)
  for i in range(num_words):
    if words[i] == "inet" and i+1 < num_words:
      return words[i+1]
  return -1

# what do you know, Darwin gets its code from BSD :)

get_bsd_interface = get_darwin_interface
get_bsd_local_ip = get_darwin_local_ip

def get_linux_local_ip(interface):
  cmd = Popen(["/sbin/ifconfig", interface], stdout=PIPE, stderr=PIPE)
  ret = cmd.wait()
  if ret !=0:
    print cmd.stderr.read()
    return -1
  words = cmd.stdout.read().split()
  for word in words:
    if word[:5] == "addr:":
      return word[5:]

def get_windows_local_ip():
  cmd = Popen(['route', 'print', '0.0.0.0'], stdout=PIPE, stderr=PIPE)
  ret = cmd.wait()
  if ret != 0:
    print cmd.stderr.read()
    return -1
  lines = cmd.stdout.read().split("\r\n")
  found_header = False
  for line in lines:
    if found_header:
      words = line.split()
      if len(words) > 3 and words[0] == '0.0.0.0':
        return words[3]
    elif (line == 'Active Routes:') | (line == 'Aktive Routen:'):  #this is language specific
      found_header = True
    
  return -1

if __name__ == "__main__":
  print "Local IP is", get_local_ip()
  
