#!/usr/bin/env python

from distutils.core import setup
import sys
import os
import os.path
import platform
import shutil

OPERATING_SYSTEM = platform.system()

# Fix up the %PATH% on Windows so that we can use Cygwin if it is  present.
if "Windows" == OPERATING_SYSTEM:
  os.environ["PATH"] += os.pathsep + r"c:\cygwin\bin"

def check_version():
  if sys.version_info < (2,4,0):
    # This is a bad start, but let's see if there is a python2.4 around:
    backup_plan = False
    if "PATH" in os.environ:
      for dir in os.environ["PATH"].split(os.pathsep):
        if os.path.exists(dir + os.sep + "python2.4"):
          backup_plan = True

    if not backup_plan:
      print "Unfortunately you need Python 2.4 to run Switzerland."
      print "Please install Python 2.4"
      print "(or send us a patch so that Switzerland runs with your version of Python ;)"
      sys.exit(1)
    else:
      print "It looks like Python2.4 is installed on your system, but it is not the"
      print 'default Python version.  Try running setup.py using "python2.4" '
      print 'instead of "python"'
      sys.exit(0)

def try_precompiled_binaries():
  plat = OPERATING_SYSTEM
  if plat == "Linux":
    return try_binary("bin/FastCollector.linux")
  elif plat == "Windows":
    return try_binary("bin\\FastCollector.exe")
  elif plat == "Darwin":
    if platform.release() < "9.0.0":
      # only try this on pre-Leopard platforms.  We don't have a sane Leopard
      # binary yet
      return try_binary("bin/FastCollector.tiger")
    else:
      return try_binary("bin/FastCollector.leopard")
  return False

def try_binary(path):
  if not os.path.exists(path):
    print "Cannot try precompiled binary %s," % path
    print "(probably because you are in the wrong directory....)"
    return False
  print "Testing executable %s:" % path
  try:
    from subprocess import Popen, PIPE
    # os.chmod does not work on, of all platforms, Windows, where cygwin may
    # nonetheless require it.
    p=Popen("chmod a+x " + path, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.wait()
  except:
    pass
  inp,outp,errors = os.popen3(path+ " -d notadeviceanywhere")
  line = errors.read()
  if "Couldn't" in line:
    # magic to keep things quiet
    print "Looks like it executes on this machine!"
    return path
  print "This is what we got when we tried the precompiled binary:\n%s" % line[:-1]
  print "Looks like that isn't going to work :("
  return False

source = os.path.join("switzerland", "client", "FastCollector.c")
if OPERATING_SYSTEM == "Windows":
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

def try_gcc_compile_static_libpcap():
  cmd = "gcc -O3 -lpcap `locate libpcap.a | head -1` -o %s %s" % (dest,source)
  print "Trying compile:", cmd
  os.system(cmd)
  if try_binary(dest):
    return dest
  else:
    return False

def try_vaguely_responsible_compile():
  cc = os.environ.get("CC", "gcc")
  cflags = os.environ.get("CFLAGS", "")
  ldflags = os.environ.get("LDFLAGS", "")

  cmd = cc + " " + cflags + " " + ldflags + (" -lpcap -o %s %s" % (dest,source))

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

    attempts = try_gcc_compile() or try_cc_compile() or \
          try_vaguely_responsible_compile() or try_gcc_compile_static_libpcap()
    if attempts:
      print "Compile successful!"
    else:
      print "No luck with compilers"
    return attempts

def ntpdate_runs():
  "No guarantees that it does what you want..."
  try:
    print "Checking to see if we can execute ntpdate"
    from subprocess import Popen, PIPE
    p = Popen("ntpdate", stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.wait()
    return True
  except ImportError:
    print "Can't test ntpdate with old pythons, assuming ntpdate works..."
    return True
  except:
    print "No ntpdate executable in the PATH..."
    return False

def main():
  check_version()
  if OPERATING_SYSTEM == "Windows":
      shutil.copyfile("switzerland-client", "switzerland-client.py")
      shutil.copyfile("switzerland-server", "switzerland-server.py")
      executables = ["switzerland-client.py","switzerland-server.py"]
      if not ntpdate_runs():
        executables.append("bin\\ntpdate.exe")
  else:
      executables = ["switzerland-client","switzerland-server"]
  bin = find_binary()
  if bin: 
    if bin != dest:
      # Since FastCollector.linux isn't what we wan't in /usr/bin 
      shutil.copy(bin,dest)
    executables.append(dest)


# Gah.  It would be fair to say that distutils sucks.  The following hack
# adding the undocumented -f flag is necessary to ensure that the installer
# overwrites outdated previously installed versions of Switzerland.
  if sys.argv[-1] == "install":
    sys.argv.append("--force")

  setup(name = "Switzerland",
        version = "0.0.7",
        description = "EFF Network Testing System",
        author = "Peter Eckersley, Jered Wierzbicki and Steven Lucy",
        author_email = "switzerland-devel@eff.org",
        url = "http://www.eff.org/testyourisp/switzerland",
        packages = ["switzerland", "switzerland.lib","switzerland.client",\
                    "switzerland.common","switzerland.server"],
        scripts = executables,
       )
  if "install" in sys.argv:
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

main()
