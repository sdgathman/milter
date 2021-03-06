#!/usr/bin/python3
import cgi
import cgitb; cgitb.enable()
import os
import re

template_re = re.compile(r'\%([A-Za-z0-9_]*)')
R = re.compile(r'%+')

def output(DATA):
  def getfield(name):
    return R.sub(lambda t: '%'*((t.end()-t.start())//2),DATA.getfirst(name,''))
    
  print("Content-type: text/html\n")
  common = "/var/www/html/python/errors/common.html"
  filename = "/var/www/html/python/errors%s.html" % os.environ["PATH_INFO"]
  with open(filename,'r') as FILE:
    body = template_re.sub(lambda m: getfield(m.expand(r'\1')), FILE.read())
  with open(common,'r') as FILE:
    t = FILE.read()
    print(t.replace('%body', body))

form = cgi.FieldStorage()

output(form)
