# -*- coding: utf-8 -*-

# file: core.py

import argparse
import os
import core
import shutil

line = '***************************************\n'
logo = ''
logo += ' _________            _            _   \n'
logo += '|__  /  _ \ _ __ ___ | |_ ___  ___| |_\n'
logo += '  / /| |_) | \'__/ _ \| __/ _ \/ __| __|\n'
logo += ' / /_|  __/| | | (_) | ||  __/ (__| |_ \n'
logo += '/____|_|   |_|  \___/ \__\___|\___|\__|\n'
#logo += line

introduction = 'An executable file static-protector.'
auther = 'By Zery (https://github.com/wangzery)'







def main():
    global filename
    global protectLv
    init()

    filePath = filename
    filePathInfo = os.path.split(filePath)
    fileName = os.path.splitext(filePathInfo[1])
    newfilePath = filePathInfo[0] + '\\' + fileName[0] + '_new' + fileName[1]
    print "[*]Output file: %s"%newfilePath
    try:
        core.protectMain(filename,protectLv)
    except:
        print "[!]Error(in main):Can't protect this file."
    try:
        shutil.copy2(filePath, newfilePath)
    except:
        print "[!]Error(in main):Can't copy this file."

def init():
    global filename
    global protectLv
    print logo
    print introduction+auther
    parser = argparse.ArgumentParser()
    parser.add_argument("filename",help='PE file which to be protected.',type=str)
    parser.add_argument("-l","--level", help="Protect level form 1 to 4.Default is the highest(4).")
    args = parser.parse_args()
    filename = args.filename
    if args.level:
        protectLv = args.level
    else:
        protectLv = 4



if __name__ == '__main__':
    main()