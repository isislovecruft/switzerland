#!/usr/bin/env python2.5

import sys
from subprocess import Popen,PIPE
import logging
import traceback
import platform
import os

log = logging.getLogger('alice.time_manager')

class UncertainTimeError(Exception):
  pass

class TimeManager:

  def __init__(self):
    
    self.ntp_sysinfo = {}

    # get_time_error is the function Alice will call to get an estimate
    # of the inaccuracy of her clock.  Ideally we use ntpd's measure of
    # root dispersion, but that can be impossible for many reasons, in which
    # case we fall back to something else by switching out this function 
    self.get_time_error = self.ntpd_root_dispersion

    log.info("Looking for ntpd...")
    try:
      ntpdc = Popen("ntpdc", stdin=PIPE, stderr=PIPE, stdout=PIPE)
    except:
      log.info("Couldn't run ntpdc.  Will try something else...")
      log.debug(traceback.format_exc())
      self.get_time_error = self.ntpdate_poll
      return
      
    ntpdc.stdin.write("sysinfo\n")
    ntpdc.stdin.close()
    self.lines = ntpdc.stdout.readlines()
    if not self.lines or "onnection refused" in self.lines[0]:
      log.info('ntpdc is present but ntpd does not appear to be alive: ("%s").  Will try something else...' % self.lines)
      self.get_time_error = self.ntpdate_poll
      return

    err = ntpdc.stderr.readlines()
    if err:
      log.info('error running ntpdc: ("%s")' % err)
      self.get_time_error = self.ntpdate_poll
      return
      
    for line in self.lines:
      pos = line.find(":")
      key = line[:pos].lower()
      val = line[pos+1:].strip()
      self.ntp_sysinfo[key]=val

    mode = self.ntp_sysinfo["system peer mode"]
    if mode == "unspec":
      log.info("""
      NTP is in "unspec" mode.  This is probably because your system clock
      is wrong by seconds or more.  Switzerland won't work if your clock is
      that wrong.  Unspec mode could also mean that you're offline or that 
      you need to give NTP another minute or two to find time servers.  If 
      this doesn't work, try stopping NTP, use the ntpdate program to adjust 
      the clock and then start NTP again.""")
      log.info("Will try something else...")
      self.get_time_error = self.ntpdate_poll
    elif mode != "client":
      log.info("Note that NTP is in mode %s", mode)


  def query_timeserver(self, timeserver):
    '''Query a timeserver using ntpdate and return the clock delta'''
    try:
      import re
      regex = re.compile("offset (-?[0-9]+\.[0-9]+) sec")
      executable = "ntpdate"
      # try bin/ntpdate if ntpdate doesn't work
      try:
        Popen(executable, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False)
      except:
        executable = os.path.join("bin", "ntpdate")
      if platform.system() == "Windows":
        cmd = [executable,"-b","-q",timeserver]
        cmd = " ".join(cmd)
        ntpdate = Popen(cmd, stdin=PIPE, stderr=PIPE, stdout=PIPE, shell=True)
      else:
        cmd = [executable,"-q",timeserver]        
        ntpdate = Popen(cmd, stdin=PIPE, stderr=PIPE, stdout=PIPE)
      ntpdate_lines = ntpdate.stdout.read()
      match = regex.search(ntpdate_lines)
      if not match:
        log.error("Failed to parse the output from ntpdate.")
        log.debug(ntpdate_lines)
        return None
      delta = float(match.group(1))
      return abs(delta)

    except:
      log.warn("Weird but possibly non-fatal error:\n"+traceback.format_exc())
      return None

  def ntpdate_poll(self):
    '''An alternative method for finding the root dispersion'''
    servers = ["0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org"]
    try:
      results = [self.query_timeserver(s) for s in servers]
      results = filter(lambda r : r != None, results)
      if results:
        log.debug("ntpdate poll results are: %s" % results)
        log.info("Taking the maximum error reported by %d timeservers" % 
                 len(results))
        log.info("Not quite as good as a working ntpd, but this should be ok")
        return max(results)
      else:
        log.info("We haven't succeeded in polling any NTP servers, either.")
        raise UncertainTimeError
    except:
      log.debug("ntpdate_poll error:\n%s" % traceback.format_exc())
      raise UncertainTimeError

  def ntpd_root_dispersion(self):
    try:
        
      mode = self.ntp_sysinfo["system peer mode"]
      return float(self.ntp_sysinfo["root dispersion"].split()[0])
    except KeyError:		 
      # try to use ntpdate to calculate the root dispersion by finding the max 
      # deviation as reported by 3 time servers
      log.warning("Couldn't find root dispersion via ntpdc.  Trying ntpdate...")
      return self.ntpdate_poll()


if __name__ == "__main__":
  x = TimeManager()
  print x.get_time_error()
    
# vim: et ts=2
