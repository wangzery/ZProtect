# -*- coding: utf-8 -*-

# file: register.py

from capstone import *
from capstone.x86 import *

# 定义所有寄存器
# x86:
ebp = 'EBP'
esp = 'ESP'
eax = 'EAX'
ebx = 'EBX'
ecx = 'ECX'
edx = 'EDX'
esi = 'ESI'
edi = 'EDI'
eip = 'EIP'

register_X86 = [ebp,esp,eax,ebx,ecx,edx,esi,edi,eip]

CONDJMPCODE = [X86_INS_JA, X86_INS_JAE, X86_INS_JB, X86_INS_JBE, X86_INS_JCXZ, X86_INS_JE, X86_INS_JECXZ,
               X86_INS_JG, X86_INS_JGE, X86_INS_JL, X86_INS_JLE, X86_INS_JNE, X86_INS_JNO, X86_INS_JNP,
               X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ, X86_INS_JS]

# for test
'''if __name__ == '__main__':
    print ebp
    print X86_REG_EBP'''

