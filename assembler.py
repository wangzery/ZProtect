# -*- coding: utf-8 -*-

# file: assembler.py
#
# 封装几个用到的汇编指令
#

from keystone import *
from register import *


def push(arg):
    try:
        if isinstance(arg, str):
            # push reg
            CODE = b"push " + bytes(arg)
        elif isinstance(arg, int):
            # push imm
            CODE = b"push " + str(arg)
        else:
            raise Exception("[!]ERROR(in assembler_push):Argument[1] of push is invalid.")
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except:
        print("[!]ERROR(in assembler_push):assembling 'push %s' failed." % arg)


def pop(arg):
    try:
        if isinstance(arg, str):
            # pop reg
            CODE = b"pop " + bytes(arg)
        else:
            raise Exception("[!]ERROR(in assembler_pop):Argument[1] of pop is invalid.")
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except :
        print("[!]ERROR(in assembler_pop):assembling 'pop %s' failed." % arg)


def ret():
    try:
        CODE = b"ret"
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except KsError as e:
        print("[!]ERROR(in assembler_ret):assembling 'ret' failed.")


def mov(arg1, arg2):
    try:
        if isinstance(arg1, str) and isinstance(arg2, str):
            # mov reg1,reg2
            CODE = b"mov " + bytes(arg1) + ',' + bytes(arg2)
        elif isinstance(arg1, str) and isinstance(arg2, int):
            # mov reg,imm
            CODE = b"mov " + bytes(arg1) + ',' + str(arg2)
        else:
            raise Exception("[!]ERROR(in assembler_mov):Arguments of mov is invalid.[%s,%s]" % arg1, arg2)
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except:
        print("[!]ERROR(in assembler_mov):assembling 'mov %s,%s' failed." % arg1, arg2)


def add(arg1, arg2):
    try:
        if isinstance(arg1, str) and isinstance(arg2, str):
            # add reg1,reg2
            CODE = b"add " + bytes(arg1) + ',' + bytes(arg2)
        elif isinstance(arg1, str) and isinstance(arg2, int):
            # add reg,imm
            CODE = b"add " + bytes(arg1) + ',' + str(arg2)
        else:
            raise Exception("[!]ERROR(in assembler_add):Arguments of add is invalid.[%s,%s]" % arg1, arg2)
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except KsError as e:
        print("[!]ERROR(in assembler_add):assembling 'add %s,%s' failed." % arg1, arg2)


def sub(arg1, arg2):
    try:
        if isinstance(arg1, str) and isinstance(arg2, str):
            # sub reg1,reg2
            CODE = b"sub " + bytes(arg1) + ',' + bytes(arg2)
        elif isinstance(arg1, str) and isinstance(arg2, int):
            # sub reg,imm
            CODE = b"sub " + bytes(arg1) + ',' + str(arg2)
        else:
            raise Exception("[!]ERROR(in assembler_sub):Arguments of sub is invalid.[%s,%s]" % arg1, arg2)
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except :
        print("[!]ERROR(in assembler_sub):assembling 'sub %s,%s' failed."%arg1,arg2)


def jmp(arg):
    try:
        if isinstance(arg, str):
            # jmp reg
            CODE = b"jmp " + bytes(arg)
        elif isinstance(arg, int):
            # jmp imm
            CODE = b"jmp " + str(arg)
        else:
            raise Exception("[!]ERROR(in assembler_jmp):Argument[1] of jmp is invalid.")
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except:
        print("[!]ERROR(in assembler_jmp):assembling 'jmp %s' failed."%arg)


def call(arg):
    try:
        if isinstance(arg, str):
            # call reg
            CODE = b"call " + bytes(arg)
        elif isinstance(arg, int):
            # call imm
            CODE = b"call " + str(arg)
        else:
            raise Exception("[!]ERROR(in assembler_call):Argument[1] of call is invalid.")
        asmCode = assembling(CODE)
        return bytearray(asmCode)
    except:
        print("[!]ERROR(in assembler_call):assembling 'call %s' failed."%arg)


def assembling(CODE):
    try:
        # 初始化汇编引擎
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
        # print("%s = %s (number of statements: %u)" % (CODE, encoding, count))
        asmCode = ''
        for i in encoding:
            # print "%02x"%i
            asmCode += b"%02x" % i
        return asmCode
    except KsError as e:
        print("[!]ERROR(in assembler_assembling): %s" % e)



# for test
if __name__ == '__main__':
    print ret()
    print push(0x1)
    print call(0x00401234)
