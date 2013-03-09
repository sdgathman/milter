import unittest
import doctest
import Milter
import bms
from Milter.test import TestBase
import mime
import rfc822
import StringIO
import email
import sys
#import pdb

try:
  def DNSLookup(name,qtype,strict=True,timeout=None): return []
  import spf
  spf.DNSLookup = DNSLookup
except: pass

class TestMilter(TestBase,bms.bmsMilter):
  def __init__(self):
    TestBase.__init__(self)
    bms.bmsMilter.__init__(self)
    #self.setsymval('j','test.milter.org')
    pass

class BMSMilterTestCase(unittest.TestCase):

  def testDefang(self,fname='virus1'):
    milter = TestMilter()
    rc = milter.connect('testDefang')
    self.assertEqual(rc,Milter.CONTINUE)
    rc = milter.feedMsg(fname)
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus1.out","r").read())
    fp.seek(0)
    msg = mime.message_from_file(fp)
    str = msg.get_payload(1).get_payload()
    milter.log(str)
    milter.close()

  # test some spams that crashed our parser
  def testParse(self,fname='spam7'):
    milter = TestMilter()
    milter.connect('testParse')
    rc = milter.feedMsg(fname)
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Milter needlessly replaced body.")
    fp = milter._body
    open('test/'+fname+".tstout","w").write(fp.getvalue())
    milter.connect('pro-send.com')
    rc = milter.feedMsg('spam8')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg('bounce')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg('bounce1')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Milter needlessly replaced body.")
    milter.close()

  def testDefang2(self):
    milter = TestMilter()
    milter.connect('testDefang2')
    rc = milter.feedMsg('samp1')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Milter needlessly replaced body.")
    rc = milter.feedMsg("virus3")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus3.tstout","w").write(fp.getvalue())
    #self.failUnless(fp.getvalue() == open("test/virus3.out","r").read())
    rc = milter.feedMsg("virus6")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    self.failUnless(milter._headerschanged,"Message headers not adjusted")
    fp = milter._body
    open("test/virus6.tstout","w").write(fp.getvalue())
    milter.close()

  def testDefang3(self):
    milter = TestMilter()
    milter.connect('testDefang3')
    # test script removal on complex HTML attachment
    rc = milter.feedMsg('amazon')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/amazon.tstout","w").write(fp.getvalue())
    # test defanging Klez virus
    rc = milter.feedMsg("virus13")
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    fp = milter._body
    open("test/virus13.tstout","w").write(fp.getvalue())
    # test script removal on quoted-printable HTML attachment
    # sgmllib can't handle the <![if cond]> syntax
    rc = milter.feedMsg('spam44')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failIf(milter._bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/spam44.tstout","w").write(fp.getvalue())
    milter.close()
 
  def testRFC822(self):
    milter = TestMilter()
    milter.connect('testRFC822')
    # test encoded rfc822 attachment
    #pdb.set_trace()
    rc = milter.feedMsg('test8')
    self.assertEqual(rc,Milter.ACCEPT)
    # python2.4 doesn't scan encoded message attachments
    if sys.hexversion < 0x02040000:
      self.failUnless(milter._bodyreplaced,"Message body not replaced")
    #self.failIf(milter._bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/test8.tstout","w").write(fp.getvalue())
    rc = milter.feedMsg('virus7')
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._bodyreplaced,"Message body not replaced")
    #self.failIf(milter._bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/virus7.tstout","w").write(fp.getvalue())

  def testSmartAlias(self):
    milter = TestMilter()
    milter.connect('testSmartAlias')
    # test smart alias feature
    key = ('foo@example.com','baz@bat.com')
    bms.smart_alias[key] = ['ham@eggs.com']
    rc = milter.feedMsg('test8',key[0],key[1])
    self.assertEqual(rc,Milter.ACCEPT)
    self.failUnless(milter._delrcpt == ['<baz@bat.com>'])
    self.failUnless(milter._addrcpt == ['<ham@eggs.com>'])
    # python2.4 email does not decode message attachments, so script
    # is not replaced
    if sys.hexversion < 0x02040000:
      self.failUnless(milter._bodyreplaced,"Message body not replaced")

  def testBadBoundary(self):
    milter = TestMilter()
    milter.connect('testBadBoundary')
    # test rfc822 attachment with invalid boundaries
    #pdb.set_trace()
    rc = milter.feedMsg('bound')
    if sys.hexversion < 0x02040000:
      # python2.4 adds invalid boundaries to decects list and makes
      # payload a str
      self.assertEqual(rc,Milter.REJECT)
      self.assertEqual(milter._reply[0],'554')
    #self.failUnless(milter._bodyreplaced,"Message body not replaced")
    self.failIf(milter._bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/bound.tstout","w").write(fp.getvalue())

  def testCompoundFilename(self):
    milter = TestMilter()
    milter.connect('testCompoundFilename')
    # test rfc822 attachment with invalid boundaries
    #pdb.set_trace()
    rc = milter.feedMsg('test1')
    self.assertEqual(rc,Milter.ACCEPT)
    #self.failUnless(milter._bodyreplaced,"Message body not replaced")
    self.failIf(milter._bodyreplaced,"Message body replaced")
    fp = milter._body
    open("test/test1.tstout","w").write(fp.getvalue())

  def testFindsrs(self):
    if not bms.srs:
      import SRS
      bms.srs = SRS.new(secret='test')
    sender = bms.srs.forward('foo@bar.com','mail.example.com')
    sndr = bms.findsrs(StringIO.StringIO(
"""Received: from [1.16.33.86] (helo=mail.example.com)
	by bastion4.mail.zen.co.uk with smtp (Exim 4.50) id 1H3IBC-00013b-O9
	for foo@bar.com; Sat, 06 Jan 2007 20:30:17 +0000
X-Mailer: "PyMilter-0.8.5"
	<%s> foo
MIME-Version: 1.0
Content-Type: text/plain
To: foo@bar.com
From: postmaster@mail.example.com
""" % sender
    ))
    self.assertEqual(sndr,'foo@bar.com')

  def testBanned(self):
    bd = set(('*.foo.bar','*.info','baz.bar'))
    self.assertTrue(bms.isbanned('bif.foo.bar',bd))
    self.assertFalse(bms.isbanned('bif.foo.com',bd))
    self.assertTrue(bms.isbanned('foo.info',bd))
    self.assertFalse(bms.isbanned('foo.baz.bar',bd))
    self.assertTrue(bms.isbanned('baz.bar',bd))

#  def testReject(self):
#    "Test content based spam rejection."
#    milter = TestMilter()
#    milter.connect('gogo-china.com')
#    rc = milter.feedMsg('big5');
#    self.failUnless(rc == Milter.REJECT)
#    milter.close();

def suite(): 
  s = unittest.makeSuite(BMSMilterTestCase,'test')
  s.addTest(doctest.DocTestSuite(bms))
  return s

if __name__ == '__main__':
  if len(sys.argv) > 1:
    for fname in sys.argv[1:]:
      milter = TestMilter()
      milter.connect('main')
      fp = open(fname,'r')
      rc = milter.feedFile(fp)
      fp = milter._body
      sys.stdout.write(fp.getvalue())
  else:
    #unittest.main()
    unittest.TextTestRunner().run(suite())
