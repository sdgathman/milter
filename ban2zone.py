#!/usr/bin/python2.4

import socket
import struct
import sys
from glob import glob

def coverage(banned_ips,min=128):
  lastcnet = None
  bits = 0
  bitcnt = 0
  for ip in (struct.unpack('!I',i)[0] for i in banned_ips):
    cnet = ip & 0xFFFFFF00
    if cnet != lastcnet:
      if lastcnet is not None:
        if bitcnt > min: yield lastcnet,bitcnt,bits
      bits = 0L
      bitcnt = 0
      lastcnet = cnet
    bit = ip & 0xFF
    bits |= 1L<<bit
    bitcnt += 1
  if lastcnet is not None:
    if bitcnt > min: yield lastcnet,bitcnt,bits

banned_ips = set(socket.inet_aton(ip) 
    for fn in sys.argv[1:]
    for ip in open(fn))
banned_ips.difference_update(socket.inet_aton(ip)
    for ip in open('whitelist_ips'))
ips = list(banned_ips)
ips.sort()

for cnet,bitcnt,bits in coverage(ips,128):
  ip = socket.inet_ntoa(struct.pack('!I',cnet)).split('.')
  ip[-1] = '*'
  ip.reverse()
  print "%s\tIN A 127.0.0.2 ; %d ips banned"%('.'.join(ip),bitcnt)
  banned_ips.difference_update(struct.pack('!I',cnet + i) for i in range(256))

del ips

banned_ips = list(banned_ips)
banned_ips.sort()

for ip in banned_ips:
  a = socket.inet_ntoa(ip).split('.')
  a.reverse()
  print "%s\tIN A 127.0.0.2"%('.'.join(a))
