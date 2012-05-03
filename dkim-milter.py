# A simple DKIM milter.
# You must install pydkim/dkimpy for this to work.

# http://www.sendmail.org/doc/sendmail-current/libmilter/docs/installation.html

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2007 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import Milter
import dkim
import logging
import logging.config
import os
import tempfile
import StringIO
from Milter.config import MilterConfigParser
from Milter.utils import iniplist,parse_addr

class Config(object):
  "Hold configuration options."
  pass

def read_config(list):
  "Return new config object."
  for fn in list:
    if os.access(fn,os.R_OK):
      logging.config.fileConfig(fn)
      break
  cp = MilterConfigParser()
  cp.read(list)
  if cp.has_option('milter','datadir'):
        os.chdir(cp.get('milter','datadir'))
  conf = Config()
  conf.log = logging.getLogger('dkim-milter')
  conf.log.info('logging started')
  conf.socketname = cp.getdefault('milter','socketname', '/tmp/dkimmiltersock')
  conf.miltername = cp.getdefault('milter','name','pydkimfilter')
  conf.internal_connect = cp.getlist('milter','internal_connect')
  # DKIM section
  if cp.has_option('dkim','privkey'):
    conf.keyfile = cp.getdefault('dkim','privkey')
    conf.selector = cp.getdefault('dkim','selector','default')
    conf.domain = cp.getdefault('dkim','domain')
    if conf.keyfile and conf.domain:
      try:
	with open(conf.keyfile,'r') as kf:
	  conf.key = kf.read()
      except:
	conf.log.error('Unable to read: %s',conf.keyfile)
  return conf

  
class dkimMilter(Milter.Base):
  "Milter to check and sign DKIM.  Each connection gets its own instance."

  def log(self,*msg):
    self.conf.log.info('[%d] %s' % (self.id,' '.join([str(m) for m in msg])))

  def __init__(self):
    self.mailfrom = None
    self.id = Milter.uniqueID()
    # we don't want config used to change during a connection
    self.conf = config
    self.fp = None

  @Milter.noreply
  def connect(self,hostname,unused,hostaddr):
    self.internal_connection = False
    self.hello_name = None
    # sometimes people put extra space in sendmail config, so we strip
    self.receiver = self.getsymval('j').strip()
    if hostaddr and len(hostaddr) > 0:
      ipaddr = hostaddr[0]
      if iniplist(ipaddr,self.conf.internal_connect):
	self.internal_connection = True
    else: ipaddr = ''
    self.connectip = ipaddr
    if self.internal_connection:
      connecttype = 'INTERNAL'
    else:
      connecttype = 'EXTERNAL'
    self.log("connect from %s at %s %s" % (hostname,hostaddr,connecttype))
    return Milter.CONTINUE

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  @Milter.noreply
  def envfrom(self,f,*str):
    self.log("mail from",f,str)
    self.fp = StringIO.StringIO()
    self.mailfrom = f
    t = parse_addr(f)
    if len(t) == 2: t[1] = t[1].lower()
    self.canon_from = '@'.join(t)
    self.user = self.getsymval('{auth_authen}')
    if self.user:
      # Very simple SMTP AUTH policy by default:
      #   any successful authentication is considered INTERNAL
      # Detailed authorization policy is configured in the access file below.
      self.internal_connection = True
      self.log(
        "SMTP AUTH:",self.user, self.getsymval('{auth_type}'),
        "sslbits =",self.getsymval('{cipher_bits}'),
        "ssf =",self.getsymval('{auth_ssf}'), "INTERNAL"
      )
    return Milter.CONTINUE

  @Milter.noreply
  def header(self,name,val):
    if self.fp:
      self.fp.write("%s: %s\n" % (name,val))
    return Milter.CONTINUE

  @Milter.noreply
  def eoh(self):
    if self.fp:
      self.fp.write("\n")                         # terminate headers
    self.bodysize = 0
    return Milter.CONTINUE

  @Milter.noreply
  def body(self,chunk):         # copy body to temp file
    if self.fp:
      self.fp.write(chunk)      # IOError causes TEMPFAIL in milter
      self.bodysize += len(chunk)
    return Milter.CONTINUE

  def eom(self):
    if not self.fp:
      return Milter.ACCEPT      # no message collected - so no eom processing

    self.fp.seek(0)
    txt = self.fp.read()
    if self.internal_connection:
      self.sign_dkim(txt)
    else:
      self.check_dkim(txt)
    return Milter.CONTINUE

  def sign_dkim(self,txt):
      conf = self.conf
      try:
        d = dkim.DKIM(txt,logger=conf.log)
	h = d.sign(conf.selector,conf.domain,conf.key,
                canonicalize=('relaxed','simple'))
	name,val = h.split(':',1)
        self.addheader(name,val)
      except dkim.DKIMException as x:
	self.log('DKIM: %s'%x)
      except Exception as x:
	conf.log.error("sign_dkim: %s",x,exc_info=True)
      
  def check_dkim(self,txt):
      res = False
      conf = self.conf
      try:
        d = dkim.DKIM(txt,logger=conf.log)
	res = d.verify()
      except dkim.DKIMException as x:
	self.log('DKIM: %s'%x)
      except Exception as x:
	conf.log.error("check_dkim: %s",x,exc_info=True)
      if res:
	self.log('DKIM: Pass (%s)'%d.domain)
        self.dkim_domain = d.domain
      else:
	fd,fname = tempfile.mkstemp(".dkim")
	with os.fdopen(fd,"w+b") as fp:
	  fp.write(txt)
	self.log('DKIM: Fail (saved as %s)'%fname)
      return res

if __name__ == "__main__":
  Milter.factory = dkimMilter
  Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
  global config
  config = read_config(['dkim-milter.cfg','/etc/mail/dkim-milter.cfg'])
  miltername = config.miltername
  socketname = config.socketname
  print """To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=%s
X%s,        S=local:%s

See the sendmail README for libmilter.
sample dkim-milter startup""" % (miltername,miltername,socketname)
  sys.stdout.flush()
  Milter.runmilter(miltername,socketname,240)
  print "sample dkim-milter shutdown"
