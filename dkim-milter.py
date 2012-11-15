# A simple DKIM milter.
# You must install pydkim/dkimpy for this to work.

# http://www.sendmail.org/doc/sendmail-current/libmilter/docs/installation.html

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2007 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import Milter
import dkim
from dkim.dnsplug import get_txt
from dkim.util import parse_tag_value
import authres
import logging
import logging.config
import os
import tempfile
import StringIO
import re
from Milter.config import MilterConfigParser
from Milter.utils import iniplist,parse_addr,parseaddr

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
    conf.reject = cp.getdefault('dkim','reject')
    if conf.keyfile and conf.domain:
      try:
	with open(conf.keyfile,'r') as kf:
	  conf.key = kf.read()
      except:
	conf.log.error('Unable to read: %s',conf.keyfile)
  return conf

FWS = re.compile(r'\r?\n[ \t]+')
  
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
    self.has_dkim = False
    self.author = None
    self.arheaders = []
    self.arresults = []
    if self.user:
      # Very simple SMTP AUTH policy by default:
      #   any successful authentication is considered INTERNAL
      self.internal_connection = True
      auth_type = self.getsymval('{auth_type}')
      ssl_bits =  self.getsymval('{cipher_bits}')
      self.log(
        "SMTP AUTH:",self.user,"sslbits =",ssl_bits, auth_type,
        "ssf =",self.getsymval('{auth_ssf}'), "INTERNAL"
      )
      # Detailed authorization policy is configured in the access file below.
      self.arresults.append(
        authres.SMTPAUTHAuthenticationResult(result = 'pass',
      	result_comment = auth_type+' sslbits='+ssl_bits, smtp_auth = self.user)
      )
    return Milter.CONTINUE

  @Milter.noreply
  def header(self,name,val):
    lname = name.lower()
    if not self.has_dkim and lname == 'dkim-signature':
      self.log("%s: %s" % (name,val))
      self.has_dkim = True
    if lname == 'from':
      fname,self.author = parseaddr(val)
      self.log("%s: %s" % (name,val))
    elif lname == 'authentication-results':
      self.arheaders.append(val)
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
    # lookup Author Domain Signing Policy, if any
    adsp = { 'dkim': 'unknown' }
    if self.author:
      author_domain = self.author.split('@',1)[-1]
      s = get_txt('_adsp._domainkey.'+author_domain)
      if s:
	m = parse_tag_value(s)
	if m.has_key('dkim'):
	  self.log(s)
	  adsp = m
    # Remove existing Authentication-Results headers for our authserv_id
    for i,val in enumerate(self.arheaders,1):
      # FIXME: don't delete A-R headers from trusted MTAs
      ar = authres.AuthenticationResultsHeader.parse_value(FWS.sub('',val))
      if ar.authserv_id == self.receiver:
	self.chgheader('authentication-results',i,'')
	self.log('REMOVE: ',val)
    # Check or sign DKIM
    self.fp.seek(0)
    if self.internal_connection:
      txt = self.fp.read()
      self.sign_dkim(txt)
      result = None
    elif self.has_dkim:
      txt = self.fp.read()
      if self.check_dkim(txt):
        result = 'pass'
      else:
        result = 'fail'
      self.arresults.append(
        authres.DKIMAuthenticationResult(result=result,
	  header_i = self.header_i, header_d = self.header_d,
	  result_comment = self.dkim_comment)
      )
    else:
      result = 'none'
    # Check if local reject policy and ADSP indicate message should be rejected
    lp = self.conf.reject	# local policy
    if lp and result and result != 'pass':
      p = adsp['dkim']		# author domain policy
      if lp == p or p == 'discardable' and lp == 'all':
        if result == 'none':
	  t = 'Missing'
	else:
	  t = 'Invalid'
	self.setreply('550','5.7.1',
	  '%s DKIM signature for %s with ADSP dkim=%s'%(t,self.author,p))
	self.log('REJECT: %s DKIM signature'%t)
	return Milter.REJECT
    if self.arresults:
      h = authres.AuthenticationResultsHeader(authserv_id = self.receiver, 
	results=self.arresults)
      self.log(h)
      name,val = str(h).split(': ',1)
      self.addheader(name,val,0)
    return Milter.CONTINUE

  def sign_dkim(self,txt):
      conf = self.conf
      try:
        d = dkim.DKIM(txt,logger=conf.log)
	h = d.sign(conf.selector,conf.domain,conf.key,
                canonicalize=('relaxed','simple'))
	name,val = h.split(': ',1)
        self.addheader(name,val.strip().replace('\r\n','\n'),0)
      except dkim.DKIMException as x:
	self.log('DKIM: %s'%x)
      except Exception as x:
	conf.log.error("sign_dkim: %s",x,exc_info=True)
      
  def check_dkim(self,txt):
      res = False
      conf = self.conf
      d = dkim.DKIM(txt,logger=conf.log)
      try:
	res = d.verify()
	if res:
	  self.dkim_comment = 'Good %d bit signature.' % d.keysize
	else:
	  self.dkim_comment = 'Bad %d bit signature.' % d.keysize
      except dkim.DKIMException as x:
	self.dkim_comment = str(x)
	#self.log('DKIM: %s'%x)
      except Exception as x:
	self.dkim_comment = str(x)
	conf.log.error("check_dkim: %s",x,exc_info=True)
      self.header_i = d.signature_fields.get(b'i')
      self.header_d = d.signature_fields.get(b'd')
      if res:
	#self.log('DKIM: Pass (%s)'%d.domain)
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
