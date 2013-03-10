#!/usr/bin/python2.6
import unittest
import Milter
import spfmilter
import spf
from Milter.test import TestBase
import sys

zonedata = { }

def DNSLookup(name,qtype,strict=True,timeout=None):
  try:
    #print name,qtype
    timeout = True

    # emulate pydns-2.3.0 label processing
    a = []
    for label in name.split('.'):
      if label:
        if len(label) > 63:
          raise spf.TempError('DNS label too long')
        a.append(label)
    name = '.'.join(a)

    for i in zonedata[name.lower()]:
      if i == 'TIMEOUT':
        if timeout:
          raise spf.TempError('DNS timeout')
        return
      t,v = i
      if t == qtype:
        timeout = False
      if v == 'TIMEOUT':
        if t == qtype:
          raise spf.TempError('DNS timeout')
        continue
      # keep test zonedata human readable, but translate to simulate pydns
      if t == 'AAAA':
        v = spf.inet_pton(v)
      elif type(v) == unicode:
        v = v.encode('utf-8')
      yield ((name,t),v)
  except KeyError:
    if name.startswith('error.'):
      raise spf.TempError('DNS timeout')

spf.DNSLookup = DNSLookup

class TestMilter(TestBase,spfmilter.spfMilter):
  def __init__(self):
    TestBase.__init__(self)
    spfmilter.config = spfmilter.Config()
    spfmilter.config.access_file = 'test/access.db'
    spfmilter.spfMilter.__init__(self)
    #self.setsymval('j','test.milter.org')
    pass

zonedata = {
  'example.com': [
    ('TXT', ('v=spf1 ip4:192.0.2.1',))
  ],
  'bad.example.com': [
    ('TXT', ('v=spf1 a:192.0.2.1',))
  ],
  'fail.example.com': [
    ('TXT', ('v=spf1 ip4:192.0.2.2 -all',))
  ],
  'mail.example.com': [
    ('TXT', ('v=spf1 ip4:192.0.2.1 -all',))
  ]
}

class SPFMilterTestCase(unittest.TestCase):

  def testPolicy(self):
    p = spfmilter.SPFPolicy('good@example.com',access_file='test/access.db')
    pol = p.getPolicy('smtp-auth:')
    p.close()
    self.assertEqual(pol,'OK')
    p = spfmilter.SPFPolicy('bad@example.com',access_file='test/access.db')
    pol = p.getPolicy('smtp-auth:')
    p.close()
    self.assertEqual(pol,'REJECT')
    p = spfmilter.SPFPolicy('bad@bad.example.com',access_file='test/access.db')
    pol = p.getPolicy('smtp-auth:')
    p.close()
    self.assertEqual(pol,None)
    p = spfmilter.SPFPolicy('any@random.com',access_file='test/access.db')
    pol = p.getPolicy('smtp-test:')
    p.close()
    self.assertEqual(pol,'REJECT')

  def testPass(self):
    milter = TestMilter()
    rc = milter.connect('mail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@example.com')
    self.assertEqual(rc,Milter.CONTINUE)
    milter.close()

  def testNeutral(self):
    milter = TestMilter()
    rc = milter.connect('mail.example.com',ip='192.0.2.2')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@example.com')
    self.assertEqual(rc,Milter.REJECT)
    rc = milter.connect('mail.example.com',ip='192.0.2.3')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='whatever@random.com')
    self.assertEqual(rc,Milter.CONTINUE)
    milter.close()

  def testHelo(self):
    milter = TestMilter()
    # Reject numeric HELO
    rc = milter.connect(helo='1.2.3.4',ip='192.0.3.1')
    self.assertEqual(rc,Milter.REJECT)
    milter.close()

  def testFail(self):
    milter = TestMilter()
    # Reject HELO SPF Fail when domain has no policy
    rc = milter.connect(helo='fail.example.com',ip='192.0.3.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@random.com')
    self.assertEqual(rc,Milter.REJECT)
    # HELO SPF Fail overridden by MAIL FROM Pass
    rc = milter.connect(helo='fail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@example.com')
    self.assertEqual(rc,Milter.CONTINUE)
    # HELO SPF Pass overridden by MAIL FROM Fail
    rc = milter.connect(helo='mail.example.com',ip='192.0.2.2')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@fail.example.com')
    self.assertEqual(rc,Milter.CONTINUE)
    milter.close()

  def testPermerror(self):
    milter = TestMilter()
    rc = milter.connect('mail.example.com',helo='bad.example.com',
                ip='192.0.2.2')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@example.com')
    # reject permerror on helo
    self.assertEqual(rc,Milter.REJECT)
    rc = milter.connect('mail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='clueless@bad.example.com')
    self.assertEqual(rc,Milter.REJECT)
    self.assertEqual(milter._reply[0],'550')
    self.assertEqual(milter._reply[1],'5.5.2')
    rc = milter.connect('mail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='foo@bad.example.com')
    # ignore permerror for particular localpart
    self.assertEqual(rc,Milter.CONTINUE)
    milter.close()

  def testAuth(self):
    milter = TestMilter()
    # Try a SMTP authorized user from an unauthorized IP, that is 
    # authorized to use example.com
    milter.setsymval('{auth_authen}','good')
    milter.setsymval('{cipher_bits}','256')
    milter.setsymval('{auth_ssf}','0')
    rc = milter.connect('mail.example.com',ip='192.0.3.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='grief@example.com')
    self.assertEqual(rc,Milter.CONTINUE)
    # Try a user *not* authorized to use example.com
    milter.setsymval('{auth_authen}','bad')
    rc = milter.connect('mail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good@example.com')
    self.assertEqual(rc,Milter.REJECT)
    # Try to break it by using an implicit domain
    milter.setsymval('{auth_authen}','bad')
    rc = milter.connect('mail.example.com',ip='192.0.2.1')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg('test1',sender='good')
    self.assertEqual(rc,Milter.REJECT)
    milter.close()

def suite(): 
  s = unittest.makeSuite(SPFMilterTestCase,'test')
  return s

if __name__ == '__main__':
  #unittest.main()
  import os
  cmd = None
  if os.access('test/access',os.R_OK):
    if not os.path.exists('test/access.db') or \
        os.path.getmtime('test/access') > os.path.getmtime('test/access.db'):
      cmd = 'makemap hash test/access.db <test/access'
      print cmd
      os.system(cmd)
  else:
    print "Missing test/access"
    os.exit(1)
  unittest.TextTestRunner().run(suite())
