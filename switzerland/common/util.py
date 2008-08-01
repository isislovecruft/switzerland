# Handy routines for Switzerland

import sys
import threading
import platform
import binascii
import os
import random
import time
import traceback

prot_table={}
prot_gen = False 

class DebugMe(Exception):
  pass

def __gen_prot_table():
  prot_gen = True
  try:
    if platform.system() == "Windows":
      table = open(os.path.join(os.environ['WINDIR'],'system32\\drivers\\etc\protocol'))
    else:
      table = open("/etc/protocols")
    for line in table.readlines():
      words = line.split()
      if len(words) > 0 and words[0][0] != "#":
        try:
          p1, port, p2 = words[0:3]
          port= int(port)
          prot_table[port] = p1
        except:
          pass
  except:
    print "Unable to produce protocol table"

def writable(path):
  import string
  random.seed(time.time())
  name = path + os.sep + "".join([random.choice(string.letters) for n in range(6)])
  try:
    f = open(name, "w")
  except:
    return False
  f.close()
  os.unlink(name)
  return True

def prot_name(prot_num):
  "Called from outside: return the name of a protocol number, if we can."
  if not prot_gen:
    __gen_prot_table()

  if prot_num in prot_table:
    return prot_table[prot_num]
  else:
    return prot_num

class VersionMismatch(Exception):
  pass

def bin2int(str):
  "convert a raw string to an int (Yuck!!!)"
  return int(eval("0x" + binascii.hexlify(str)))

def check_python_version():
  if platform.python_version_tuple() < ['2','5']:
    raise VersionMismatch('expecting python version 2.5 or later')

def debugger():
  import pdb
  error, value, traceback = sys.exc_info()
  print "Invoking debugger after", error, value
  pdb.post_mortem(traceback)

def screensafe(data_structure):
  "Return a representation of an untrusted data structure that's okay to print"
  str = repr(data_structure)
  if len(str) > 50:
    str = str[:50] + "..."
  return str

def set_win32_priority(pid=None,priority=1):
    """ Set The Priority of a Windows Process.  Priority is a value between 0-5 where
        2 is normal priority.  Default sets the priority of the current
        python process but can take any valid process ID. """
        
    import win32api,win32process,win32con
    
    priorityclasses = [win32process.IDLE_PRIORITY_CLASS,
                       win32process.BELOW_NORMAL_PRIORITY_CLASS,
                       win32process.NORMAL_PRIORITY_CLASS,
                       win32process.ABOVE_NORMAL_PRIORITY_CLASS,
                       win32process.HIGH_PRIORITY_CLASS,
                       win32process.REALTIME_PRIORITY_CLASS]
    if pid == None:
        pid = win32api.GetCurrentProcessId()
    handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
    win32process.SetPriorityClass(handle, priorityclasses[priority])

class ThreadLauncher(threading.Thread):
  def __init__(self, fn):
    self.fn = fn
    threading.Thread.__init__(self)
  def run(self):
    self.fn()

