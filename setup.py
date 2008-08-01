#!/usr/bin/env python

from distutils.core import setup
import sys
import os
import os.path
import platform
import shutil

def check_version():
  if sys.version_info < (2,5,0):
    # This is a bad start, but let's see if there is a python2.5 around:
    backup_plan = False
    if "PATH" in os.environ:
      for dir in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(dir + os.sep + "python2.5"):
          backup_plan = True

    if not backup_plan:
      print "Unfortunately you need Python 2.5 to run Switzerland."
      print "Please install Python 2.5"
      print "(or send us a patch so that Switzerland runs with your version of Python ;)"
      sys.exit(1)
    else:
      print "It looks like Python2.5 is installed on your system, but it is not the"
      print "default Python version.  You will need to run setup.py using python2.5"
      sys.exit(0)

def try_precompiled_binaries():
  plat = platform.system()
  if plat == "Linux":
    return try_binary("bin/FastCollector.linux")
  elif plat == "Windows":
    return try_binary("bin/FastCollector.exe")
  elif plat == "Darwin":
    return try_binary("bin/FastCollector.darwin")
  return False

def try_binary(path):
  if not os.path.exists(path):
    print "Cannot try precompiled binary %s," % path
    print "(probably because you are in the wrong directory....)"
    return False
  print "Testing executable %s:" % path
  inp,outp,errors = os.popen3(path+ " notadeviceanywhere","r")
  line = errors.read()
  if "Couldn't" in line:
    # magic to keep things quiet
    print "Looks like it executes on this machine!"
    try:
      # Remove that pesky tempfile
      line = outp.readline()
      words = line.split()
      if words[0] == "Tempfile:":
        os.unlink(words[1])
    except:
      pass
    return path
  print "This is what we got when we tried the precompiled binary:\n%s" % line[:-1]
  print "Looks like that isn't going to work :("
  return False

source = os.path.join("switzerland", "client", "FastCollector.c")
if platform.system() == "Windows":
  dest = os.path.join("switzerland", "client", "FastCollector.exe")
else:
  dest = os.path.join("switzerland", "client", "FastCollector")

def try_gcc_compile():
  cmd = "gcc -O3 -lpcap -o %s %s" % (dest,source)
  print "Trying compile:", cmd
  os.system(cmd)
  if try_binary(dest):
    return dest
  else:
    return False

def try_cc_compile():
  cmd = "cc -lpcap -o %s %s" % (dest,source)
  print "Trying compile:", cmd
  os.system(cmd)
  if try_binary(dest):
    return dest
  else:
    return False

def find_binary():
  attempt = try_precompiled_binaries()
  if attempt: 
    return attempt
  else:
    print "Trying to compile a binary for you..."

    attempts = try_gcc_compile() or try_cc_compile()
    if attempts:
      print "Compile successful!"
    else:
      print "No luck with compilers"
    return attempts

check_version()
executables = ["switzerland-client","switzerland-server"]
bin = find_binary()
if bin: 
  if bin != dest:
    # Since FastCollector.linux isn't what we wan't in /usr/bin 
    shutil.copy(bin,dest)
  executables.append(dest)

setup(name = "Switzerland",
      version = "0.0",
      description = "EFF Network Testing System",
      author = "Peter Eckersley, Jered Wierzbicki and Steven Lucy",
      author_email = "switzerland-devel@eff.org",
      url = "http://www.eff.org/testyourisp/switzerland",
      packages = ["switzerland", "switzerland.lib","switzerland.client",\
                  "switzerland.common","switzerland.server"],
      scripts = executables
     )
if not bin:
  print """
  Well, Switzerland is sort of installed, but we can't seem to obtain a
  working FastCollector executable on your machine.  Please make sure you
  have libpcap, then try again.  If it still doesn't work, make sure you
  have a C compiler and try again.  If it *still* doesn't work, go and
  compile %s yourself.  Once you've done that, make sure you put it somewhere 
  in your system PATH.  Then run Switzerland!""" % source
else:
  print "Switzerland installed successfully!"

