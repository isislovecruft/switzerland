#!/usr/bin/env python

import distutils.sysconfig
import _winreg as winreg
import win32gui, win32con
import os

script_dir = distutils.sysconfig.get_config_var('prefix') + os.sep + 'scripts'
environment = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, environment, 0, winreg.KEY_WRITE | winreg.KEY_READ)
(path, type) = winreg.QueryValueEx(k, 'Path')
    
if not script_dir in path.split(os.pathsep):
    new_path = ""
    if path.endswith(os.pathsep): # sometimes windows likes to stick an extra ; at the end
        new_path = path + script_dir + os.pathsep
    else: # other times it's sane...
        new_path = path + os.pathsep + script_dir
    print "adding "+script_dir+" to your windows %path% so switzerland can find its packet sniffer"
    winreg.SetValueEx(k, 'Path', 0, type, new_path)      
    (path, type) = winreg.QueryValueEx(k, 'Path')
    if not script_dir in path.split(os.pathsep):
        print "... well, I tried, but it didn't work.  "\
              "put " + script_dir + " in your path to run switzerland."
    else:
        print "telling open applications that your path changed (so you don't have to reboot)"
        rc, dwReturnValue = win32gui.SendMessageTimeout(win32con.HWND_BROADCAST,\
            win32con.WM_SETTINGCHANGE,\
            0, "Environment", win32con.SMTO_ABORTIFHUNG, 5000)
        print "ok, I updated your path, you should be good to go"
            
else:
      print script_dir + " is already in your windows path, should be good to go"
