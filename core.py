# -*- coding: utf-8 -*-

# file: core.py

from capstone import *
from capstone.x86 import *
import pefile
import shutil
import os
import time
import random
# TODO:assembler这个先挖个坑，慢慢填
import assembler
from register import *

# 这个功能太少了，不好用
# from peachpy.x86_64 import *

# def globle vars:
INIT_CODE = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
# filePath = r"C:\E\tmp\calc.exe"

jmpInfoList = []
condJmpInfoList = []


#
# def classes：
#
class JmpInfo:
    codeAddr = 0
    targetAddr = 0
    codeSize = 0
    jmpCode = 0
    junkCodeSize = 0

    def __init__(self):
        self.codeAddr = 0
        self.targetAddr = 0
        self.codeSize = 0
        jmpmd = Cs(CS_ARCH_X86, CS_MODE_64)
        jmpmd.detail = True
        for i in jmpmd.disasm(INIT_CODE, 1000):
            self.cmpCode = i
            break

    def setJmpInfo(self, codeAddr, targetAddr, codeSize):
        self.codeAddr = codeAddr
        self.targetAddr = targetAddr
        self.codeSize = codeSize


class CondJmpInfo(JmpInfo):
    nextCodeAddr = 0
    cmpCode = 0
    jmpCondition = 0
    jmpCondType = 0

    def __init__(self):
        cmpmd = Cs(CS_ARCH_X86, CS_MODE_64)
        cmpmd.detail = True
        for i in cmpmd.disasm(INIT_CODE, 1000):
            self.cmpCode = i
            break
        self.nextCodeAddr = 0
        self.jmpCondition = 0
        self.jmpCondType = 0
        JmpInfo.__init__(self)

    def setCondJmpInfo(self, codeAddr, targetAddr, codeSize, nextCodeAddr, jmpCondition, cmpCode, jmpCondType):
        self.setJmpInfo(codeAddr, targetAddr, codeSize)
        self.nextCodeAddr = nextCodeAddr
        self.jmpCondition = jmpCondition
        self.cmpCode = cmpCode
        self.jmpCondType = jmpCondType


class JunkCodeInfo:
    junkCode = ''
    junkCodeSize = 0
    junkCodeAddr = 0

    def __init__(self, junkCode, junkCodeSize):
        self.junkCode = junkCode
        self.junkCodeSize = junkCodeSize

    def setJunkCodeInfo(self, junkCode, junkCodeSize):
        self.junkCode = junkCode
        self.junkCodeSize = junkCodeSize


#
# def funs：
#

def getFileInfo(pe):
    global g_SizeofText
    global g_peInfo
    g_peInfo = pe
    codeblock = ''
    ep = 0
    try:
        for section in pe.sections:
            if 'text' in section.Name or 'code' in section.Name:
                # print hex(section.VirtualAddress),hex(section.Misc_VirtualSize),section.PointerToRawData,section.SizeOfRawData
                PA = section.PointerToRawData
                Size = section.SizeOfRawData
                g_SizeofText = Size
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
                print section.Name + "_Size:%s" % (ep + Size)
                codeblock = pe.get_memory_mapped_image()[ep:ep + 9999]
                # codeblock = pe.get_memory_mapped_image()[PA:PA+Size]
                break
    except:
        print '[!]Error(in getFileInfo):Analysing pe section failed.'
        return
    scanAllCode(codeblock, ep)
    # TODO:bulidAllCode完成后再关闭注释
    # bulidAllCode(codeblock, ep)
    return


def scanAllCode(codeblock, ep):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    try:
        # 先收集一遍跳转信息
        for i in md.disasm(codeblock, ep):
            iOperands = i.operands
            cmpFlag = False
            if i.id == X86_INS_CMP or i.id == X86_INS_TEST:
                print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                cmpFlag = True
                condJmpInfo = CondJmpInfo()
                condJmpInfoTemp_cmpCode = i
            elif i.id in CONDJMPCODE and cmpFlag == True and condJmpInfoTemp_cmpCode:
                print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                iNext = i.address + i.size
                print "Next:0x%x" % (iNext)
                cmpFlag = False
                condJmpInfo.setCondJmpInfo(i.address, i.op_str, i.size, iNext, i.mnemonic, condJmpInfoTemp_cmpCode,
                                           i.id)
                condJmpInfoList.append(condJmpInfo)
                del condJmpInfo
            elif i.id == X86_INS_JMP or i.id == X86_GRP_JUMP:
                print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                jmpInfo = JmpInfo()
                jmpInfo.setJmpInfo(i.address, i.op_str, i.size)
                jmpInfoList.append(jmpInfo)
                del jmpInfo
            elif i.id == X86_INS_CALL:
                # 直接寻址
                if iOperands[0].type == X86_OP_IMM:
                    print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                    jmpInfo = JmpInfo()
                    jmpInfo.setJmpInfo(i.address, i.op_str, i.size)
                    jmpInfoList.append(jmpInfo)
                    del jmpInfo
                # 间接寻址
                elif iOperands[0].type == X86_OP_MEM:
                    print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                    # 段寄存器 考虑cs的情况
                    if iOperands[0].value.mem.segment != 0:
                        print i.reg_name(iOperands[0].value.mem.base)
                    # 基址寄存器
                    if iOperands[0].value.mem.base != 0:
                        print i.reg_name(iOperands[0].value.mem.base)
                    # index寄存器
                    if iOperands[0].value.mem.index != 0:
                        print i.reg_name(iOperands[0].value.mem.index)
                    # 偏移值
                    if iOperands[0].value.mem.disp != 0:
                        print "0x%x" % iOperands[0].value.mem.disp
                        jmpInfo = JmpInfo()
                        jmpInfo.setJmpInfo(i.address, iOperands[0].value.mem.disp, i.size)
                        jmpInfoList.append(jmpInfo)
                        del jmpInfo
    except:
        print '[!]Error(in scanAllCode):Disasm BIN failed.'
    # print jmpInfoList
    # print condJmpInfoList


# genJunkCode(junkCodeSize):随机生成大小为输入参数垃圾代码
# 生成垃圾代码的几种方式：
#   1.随机复制一个大小相同的代码块
#   2.随机生成指令
#   3.随机生成16进制bytearray
def genJunkCode(junkCodeSize):
    junkCodeTypeNum = 3
    junkCodeType = random.randint(1, junkCodeTypeNum)
    codeBuf = bytearray(b'')
    if junkCodeType == 1:
        ep = g_peInfo.OPTIONAL_HEADER.AddressOfEntryPoint
        epStart = ep + random.randint(0, g_SizeofText - junkCodeSize)
        epEnd = epStart + junkCodeSize
        codeBuf += g_peInfo.get_memory_mapped_image()[epStart:epEnd]
    elif junkCodeType == 2:
        # TODO:随机生成指令
        # 随机指令类型：单目，双目，三目
        pass
    elif junkCodeType == 3:
        randHexStr = ''
        for i in range(0, junkCodeSize * 2):
            randHexStr += random.choice('0123456789abcdef')
        codeBuf = bytearray(randHexStr)
    codeInfo = JunkCodeInfo(codeBuf, len(codeBuf))
    return codeInfo


# 函数genflowercode():生成可破环栈平衡的花指令
# 生成花指令的几种方式：
# TODO：生成花指令待增加
#   1.函数头部开场代码及函数尾部收尾代码
#   2.显式及隐式的假跳转/调用/返回
#   3.随机指令的部分机器码
def genFlowerCode():

    randRangeMax = int(0xffffffff)
    randRangeMin = 0
    randomNum = random.randint(randRangeMin, randRangeMax)

    codeBuf = bytearray(b'')

    flowerCodeTypeNum = 9
    flowerCodeType = random.randint(1, flowerCodeTypeNum)
    try:
        if flowerCodeType == 1:
            codeBuf += assembler.push(ebp)
            codeBuf += assembler.mov(ebp, esp)

        elif flowerCodeType == 2:
            codeBuf += assembler.sub(esp, 0x4)
            codeBuf += assembler.pop(ebp)
            codeBuf += assembler.ret()

        elif flowerCodeType == 3:
            codeBuf += assembler.jmp(randomNum)
            codeBuf += assembler.ret()

        elif flowerCodeType == 4:
            codeBuf += bytearray(b'\xEB')
            codeBuf += bytearray(randomNum)

        elif flowerCodeType == 5:
            codeBuf += assembler.mov(esp, randomNum)
            codeBuf += assembler.ret()

        elif flowerCodeType == 6:
            codeBuf += assembler.push(randomNum)
            codeBuf += assembler.ret()

        else:
            codeBuf += bytearray(b'\x90')
    except:
        print "[!]Error(in genFlowerCode):generate flowerCode failed."

    finally:
        codeInfo = JunkCodeInfo(codeBuf, len(codeBuf))
        return codeInfo


# insertCode()在代码块的指定位置插入指定代码
# codeblock和code都是str
#
def insertCode(codeblock, pos, code):
    try:
        fCodeblock = codeblock[:pos]
        bCodeblock = codeblock[pos:]
        newCodeblock = fCodeblock + code + bCodeblock
        return newCodeblock
    except:
        print "[!]Error(in insertCode):Insert Code failed."
        return codeblock


# buildJmpCode(codeblock, ep)为无条件跳转进行混淆
# 混淆方式为在jmp后增加花指令
def buildJmpCode(codeblock, ep):
    flowerCodeInfoList = []
    newCodeBlock = codeblock
    addOffset = 0
    # 遍历插入代码
    try:
        # 先插入花指令
        for jmpInfo in jmpInfoList:
            flowerCodeInfo = genFlowerCode()
            # 记录插入点地址
            flowerCodeInfo.junkCodeAddr = jmpInfo.codeAddr + jmpInfo.codeSize
            flowerCodeInfoList.append(flowerCodeInfo)
            # 重定位插入点，需要加上已增加指令的大小
            insertPos = jmpInfo.codeAddr + jmpInfo.codeSize + addOffset - ep
            newCodeBlock = insertCode(newCodeBlock, insertPos, flowerCodeInfo.junkCode)
            jmpInfo.junkCodeSize = flowerCodeInfo.junkCodeSize
            # 修正指令地址
            jmpInfo.codeAddr += addOffset
            # 下一个jmp地址的增加量
            addOffset += jmpInfo.junkCodeSize
        # 重写jmp
        for jmpInfo in jmpInfoList:
            # 修正跳转目标地址
            for flowerCodeInfo in flowerCodeInfoList:
                # TODO:要先判断目标地址是否超出整段代码范围
                # 目标地址是否在插入点之后
                if jmpInfo.targetAddr > flowerCodeInfo.junkCodeAddr:
                    jmpInfo.targetAddr += flowerCodeInfo.junkCodeSize
            # 重建指令
            newJmpCode = assembler.jmp(jmpInfo.targetAddr)
            newNextCodeAddr = jmpInfo.codeAddr + jmpInfo.codeSize + jmpInfo.junkCodeSize
            newCodeBlocktmp = newCodeBlock[:jmpInfo.codeAddr - ep] + newJmpCode + newCodeBlock[newNextCodeAddr - ep:]
            newCodeBlock = newCodeBlocktmp
        return newCodeBlock
    except:
        print "[!]Error(in buildJmpCode):Build JmpCode failed."
        return codeblock


# TODO:为条件跳转进行混淆
#
def buildCondJmpCode(codeblock, ep):
    pass
    return codeblock


#
def bulidAllCode(codeblock, ep):
    # 添加花指令和混淆代码
    newCodeblock = codeblock
    newCodeblocklen = len(newCodeblock)
    newCodeblock = buildJmpCode(newCodeblock, ep)
    if len(newCodeblock) == newCodeblocklen:
        print "[!]Warrning(in bulidAllCode):JmpCode hasn't be built."

    newCodeblocklen = len(newCodeblock)
    newCodeblock = buildCondJmpCode(newCodeblock, ep)
    if len(newCodeblock) == newCodeblocklen:
        print "[!]Warrning(in bulidAllCode):ConditionJmpCode hasn't be built."

def protectMain(filename,protectLv):
    pass


# for test
def main():
    filePath = r"C:\E\tmp\calc.exe"
    filePathInfo = os.path.split(filePath)
    fileName = os.path.splitext(filePathInfo[1])
    newfilePath = filePathInfo[0] + '\\' + fileName[0] + '_new' + fileName[1]
    print newfilePath

    shutil.copy2(filePath, newfilePath)
    pe = pefile.PE(filePath)
    getFileInfo(pe)


if __name__ == '__main__':
    main()
