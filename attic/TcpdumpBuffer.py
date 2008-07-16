#!/usr/bin/env python2.5

import sys
sys.path.append("../common")
import subprocess

import util
import threading

# This runs in a separate process.  Its purpose is to read data from tcpdump
# in a prompt manner, to prevent tcpdump from blocking etc.

interface = sys.argv[1]

READSIZE = 10 # not sure about this

cmd = ['tcpdump','-p', '-s', '256', '-i', interface, '-w', '-', 'ip']
PIPE=subprocess.PIPE
sniffer = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE)

data_queue = []
lock = threading.Lock()
have_data = threading.Event()
closed = False

def send_data():
  try:
    while True:
      have_data.wait()
      sys.stdout.write(data_queue[0])
      del data_queue[0]
      if len(data_queue) == 0:
        # the queue is empty
        lock.acquire()
        try:
          # now that we've bothered with the lock,
          # make sure that data hasn't just arrived
          if len(data_queue) == 0:
            have_data.clear()
        finally:
          lock.release()
  finally:
    # if stdout closes or something
    global closed
    closed = True
    
      
def read_data():
  while True:
    data = sniffer.stdout.read(READSIZE)
    if data == "":
      # EOF
      print "Nothing more to do, exiting"
      retval = sniffer.wait()
      print sniffer.stderr.readlines()
      print "retval is", retval
      sys.exit(retval)

    if closed:
      sys.exit(0)

    data_queue.append(data)
    if not have_data.isSet():
      lock.acquire()
      try:
        # make sure the printer didn't send this before we signalled it
        if len(data_queue) > 0:
          have_data.set()
      finally:
        lock.release()


printer = util.ThreadLauncher(send_data)
printer.setDaemon(True)
printer.start()
read_data()
