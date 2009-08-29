import unittest
import testbms
import os

def suite(): 
  s = unittest.TestSuite()
  s.addTest(testbms.suite())
  return s

if __name__ == '__main__':
  try: os.remove('test/milter.log')
  except: pass
  unittest.TextTestRunner().run(suite())
