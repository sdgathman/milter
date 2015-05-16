# A simple SPF milter.
# You must install pyspf for this to work.

# http://www.sendmail.org/doc/sendmail-current/libmilter/docs/installation.html

# Author: Stuart D. Gathman <stuart@bmsi.com>
# Copyright 2007 Business Management Systems, Inc.
# This code is under GPL.  See COPYING for details.

import sys
import Milter
import spf
import syslog
import anydbm
from Milter.config import MilterConfigParser
from Milter.utils import iniplist,parse_addr,ip4re

syslog.openlog('spfmilter',0,syslog.LOG_MAIL)

class Config(object):
  "Hold configuration options."
  def __init__(self):
    self.internal_connect = ()
    self.trusted_relay = ()
    self.trusted_forwarder = ()
    self.access_file = None

def read_config(list):
  "Return new config object."
  cp = MilterConfigParser({
    'access_file_nulls': 'no'
  })
  cp.read(list)
  if cp.has_option('milter','datadir'):
        os.chdir(cp.get('milter','datadir'))
  conf = Config()
  conf.socketname = cp.getdefault('milter','socketname', '/tmp/spfmiltersock')
  conf.miltername = cp.getdefault('milter','name','pyspffilter')
  conf.trusted_relay = cp.getlist('milter','trusted_relay')
  conf.internal_connect = cp.getlist('milter','internal_connect')
  conf.untrapped_exception = cp.getdefault('milter','untrapped_exception',
        'CONTINUE')
  if cp.has_option('spf','trusted_forwarder'):
    conf.trusted_forwarder = cp.getlist('spf','trusted_forwarder')
  else: # backward compatibility with config typo
    conf.trusted_forwarder = cp.getlist('spf','trusted_relay')
  conf.access_file = cp.getdefault('spf','access_file',None)
  conf.access_file_nulls = cp.getboolean('spf','access_file_nulls',None)
  return conf

class SPFPolicy(object):
  "Get SPF policy by result from sendmail style access file."
  def __init__(self,sender,conf=None,access_file=None):
    if conf:
      conf = config
    if not access_file:
      access_file = conf.access_file
    if conf: 
      self.use_nulls = conf.access_file_nulls
    else:
      self.use_nulls = False
    self.sender = sender
    self.domain = sender.split('@')[-1].lower()
    if access_file:
      try:
        acf = anydbm.open(access_file,'r')
      except:
	syslog.syslog('%s: Cannot open for reading'%access_file)
	acf = None
    else: acf = None
    self.acf = acf

  def close(self):
    if self.acf:
      self.acf.close()
  def __enter__(self): return self
  def __exit__(self,t,v,b): self.close()

  def getPolicy(self,pfx):
    acf = self.acf
    if not acf: return None
    if self.use_nulls: sfx = '\x00'
    else: sfx = ''
    try:
      return acf[pfx + self.sender + sfx].rstrip('\x00')
    except KeyError:
      try:
        return acf[pfx + self.domain + sfx].rstrip('\x00')
      except KeyError:
        try:
          return acf[pfx + sfx].rstrip('\x00')
        except KeyError:
	  try:
	    return acf[pfx.rstrip(':') + sfx].rstrip('\x00')
	  except KeyError:
	    return None
  
class spfMilter(Milter.Base):
  "Milter to check SPF.  Each connection gets its own instance."

  def log(self,*msg):
    syslog.syslog('[%d] %s' % (self.id,' '.join([str(m) for m in msg])))

  def __init__(self):
    self.mailfrom = None
    self.id = Milter.uniqueID()
    # we don't want config used to change during a connection
    self.conf = config

  # addheader can only be called from eom().  This accumulates added headers
  # which can then be applied by alter_headers()
  def add_header(self,name,val,idx=-1):
    self.new_headers.append((name,val,idx))
    self.log('%s: %s' % (name,val))

  @Milter.noreply
  def connect(self,hostname,unused,hostaddr):
    self.internal_connection = False
    self.trusted_relay = False
    self.hello_name = None
    # sometimes people put extra space in sendmail config, so we strip
    self.receiver = self.getsymval('j').strip()
    if hostaddr and len(hostaddr) > 0:
      ipaddr = hostaddr[0]
      if iniplist(ipaddr,self.conf.internal_connect):
        self.internal_connection = True
      if iniplist(ipaddr,self.conf.trusted_relay):
        self.trusted_relay = True
    else: ipaddr = ''
    self.connectip = ipaddr
    if self.internal_connection:
      connecttype = 'INTERNAL'
    else:
      connecttype = 'EXTERNAL'
    if self.trusted_relay:
      connecttype += ' TRUSTED'
    self.log("connect from %s at %s %s" % (hostname,hostaddr,connecttype))
    return Milter.CONTINUE

  def hello(self,hostname):
    self.hello_name = hostname
    self.log("hello from %s" % hostname)
    if not self.internal_connection:
      # Allow illegal HELO from internal network, some email enabled copier/fax
      # type devices (Toshiba) have broken firmware.
      if ip4re.match(hostname):
        self.log("REJECT: numeric hello name:",hostname)
        self.setreply('550','5.7.1','hello name cannot be numeric ip')
        return Milter.REJECT
    return Milter.CONTINUE

  # multiple messages can be received on a single connection
  # envfrom (MAIL FROM in the SMTP protocol) seems to mark the start
  # of each message.
  def envfrom(self,f,*str):
    self.log("mail from",f,str)
    self.new_headers = []
    if not self.hello_name:
      self.log('REJECT: missing HELO')
      self.setreply('550','5.7.1',"It's polite to say helo first.")
      return Milter.REJECT
    self.mailfrom = f
    t = parse_addr(f)
    if len(t) == 2:
      t[1] = t[1].lower()
      domain = t[1]
    else:
      domain = 'localhost.localdomain'
    self.canon_from = '@'.join(t)

    # Check SMTP AUTH, also available:
    #   auth_authen  authenticated user
    #   auth_author  (ESMTP AUTH= param)
    #   auth_ssf     (connection security, 0 = unencrypted)
    #   auth_type    (authentication method, CRAM-MD5, DIGEST-MD5, PLAIN, etc)
    # cipher_bits  SSL encryption strength
    # cert_subject SSL cert subject
    # verify       SSL cert verified

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
      # Restrict SMTP AUTH users to authorized domains
      authsend = '@'.join((self.user,domain))
      with SPFPolicy(authsend,self.conf) as p:
        policy = p.getPolicy('smtp-auth:')
      if policy:
        if policy != 'OK':
          self.log("REJECT: SMTP user",self.user,
              "at",self.connectip,"not authorized for domain",domain)
          self.setreply('550','5.7.1',
            'SMTP user %s is not authorized to send from domain %s.' %
            (self.user,domain)
          )
          return Milter.REJECT
      self.log("SMTP authorized user",self.user,"sending from domain",domain)

    if not (self.internal_connection or self.trusted_relay) and self.connectip:
      return self.check_spf()
    return Milter.CONTINUE

  def eom(self):
    for name,val,idx in self.new_headers:
      try:
        self.addheader(name,val,idx)
      except:
        self.addheader(name,val)	# older sendmail can't insheader
    return Milter.CONTINUE

  def check_spf(self):
    receiver = self.receiver
    for tf in self.conf.trusted_forwarder:
      q = spf.query(self.connectip,'',tf,receiver=receiver,strict=False)
      res,code,txt = q.check()
      if res == 'pass':
        self.log("TRUSTED_FORWARDER:",tf)
        break
    else:
      q = spf.query(self.connectip,self.canon_from,self.hello_name,
	  receiver=receiver,strict=False)
      q.set_default_explanation(
	'SPF fail: see http://openspf.org/why.html?sender=%s&ip=%s' % (q.s,q.i))
      res,code,txt = q.check()
    if res not in ('pass','temperror'):
      if self.mailfrom != '<>':
	# check hello name via spf unless spf pass
        h = spf.query(self.connectip,'',self.hello_name,receiver=receiver)
        hres,hcode,htxt = h.check()
        with SPFPolicy(self.hello_name,self.conf) as hp:
          policy = hp.getPolicy('helo-%s:'%hres)
          #print 'helo-%s:%s %s'%(hres,self.hello_name,policy)
          if not policy:
            if hres in ('deny','fail','neutral','softfail'):
              policy = 'REJECT'
            else:
              policy = 'OK'
        if policy != 'OK':
          self.log('REJECT: hello SPF: %s 550 %s' % (hres,htxt))
          self.setreply('550','5.7.1',htxt,
            "The hostname given in your MTA's HELO response is not listed",
            "as a legitimate MTA in the SPF records for your domain.  If you",
            "get this bounce, the message was not in fact a forgery, and you",
            "should IMMEDIATELY notify your email administrator of the problem."
          )
          return Milter.REJECT
      else:
        hres,hcode,htxt = res,code,txt
    else: hres = None

    with SPFPolicy(q.s,self.conf) as p:
      if res == 'fail':
        policy = p.getPolicy('spf-fail:')
        if not policy or policy == 'REJECT':
          self.log('REJECT: SPF %s %i %s' % (res,code,txt))
          self.setreply(str(code),'5.7.1',txt)
          # A proper SPF fail error message would read:
          # forger.biz [1.2.3.4] is not allowed to send mail with the domain
          # "forged.org" in the sender address.  Contact <postmaster@forged.org>.
          return Milter.REJECT
      elif res == 'softfail':
        policy = p.getPolicy('spf-softfail:')
        if policy and policy == 'REJECT':
          self.log('REJECT: SPF %s %i %s' % (res,code,txt))
          self.setreply(str(code),'5.7.1',txt)
          # A proper SPF fail error message would read:
          # forger.biz [1.2.3.4] is not allowed to send mail with the domain
          # "forged.org" in the sender address.  Contact <postmaster@forged.org>.
          return Milter.REJECT
      elif res == 'permerror':
        policy = p.getPolicy('spf-permerror:')
        if not policy or policy == 'REJECT':
          self.log('REJECT: SPF %s %i %s' % (res,code,txt))
          # latest SPF draft recommends 5.5.2 instead of 5.7.1
          self.setreply(str(code),'5.5.2',txt,
            'There is a fatal syntax error in the SPF record for %s' % q.o,
            'We cannot accept mail from %s until this is corrected.' % q.o
          )
          return Milter.REJECT
      elif res == 'temperror':
        policy = p.getPolicy('spf-temperror:')
        if not policy or policy == 'REJECT':
          self.log('TEMPFAIL: SPF %s %i %s' % (res,code,txt))
          self.setreply(str(code),'4.3.0',txt)
          return Milter.TEMPFAIL
      elif res == 'neutral' or res == 'none':
        policy = p.getPolicy('spf-neutral:')
        if policy and policy == 'REJECT':
          self.log('REJECT NEUTRAL:',q.s)
          self.setreply('550','5.7.1',
    "%s requires an SPF PASS to accept mail from %s. [http://openspf.org]"
            % (receiver,q.s))
          return Milter.REJECT
      elif res == 'pass':
        policy = p.getPolicy('spf-pass:')
        if policy and policy == 'REJECT':
          self.log('REJECT PASS:',q.s)
          self.setreply('550','5.7.1',
                  "%s has been blacklisted by %s." % (q.s,receiver))
          return Milter.REJECT
    self.add_header('Received-SPF',q.get_header(res,receiver),0)
    if hres and q.h != q.o:
      self.add_header('X-Hello-SPF',hres,0)
    return Milter.CONTINUE

if __name__ == "__main__":
  Milter.factory = spfMilter
  Milter.set_flags(Milter.CHGHDRS + Milter.ADDHDRS)
  global config
  config = read_config(
    ['spfmilter.cfg','/etc/mail/spfmilter.cfg','/etc/postfix/spfmilter.cfg'])
  ue = config.untrapped_exception.upper()
  if ue == 'CONTINUE':
    Milter.set_exception_policy(Milter.CONTINUE)
  elif ue == 'REJECT':
    Milter.set_exception_policy(Milter.REJECT)
  elif ue == 'TEMPFAIL':
    Milter.set_exception_policy(Milter.TEMPFAIL)
  else:
    print("WARNING: invalid untrapped_exception policy: %s"%ue)

  miltername = config.miltername
  socketname = config.socketname
  print("""To use this with sendmail, add the following to sendmail.cf:

O InputMailFilters=%s
X%s,        S=local:%s

See the sendmail README for libmilter.
spfmilter startup""" % (miltername,miltername,socketname))
  sys.stdout.flush()
  Milter.runmilter(miltername,socketname,240)
  print "spfmilter shutdown"
