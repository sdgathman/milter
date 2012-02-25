#!/usr/bin/python2.6
import cgi
import cgitb; cgitb.enable()
import os
import re
import sys

template_re = re.compile(r'\%([A-Za-z0-9_]*)')

def output(DATA):
  print "Content-type: text/html\n"
  print "<html><body>"
  filename = "/var/www/html/python/errors%s.html" % os.environ["PATH_INFO"]
  with open(filename,'r') as FILE:
    print template_re.sub(lambda m: DATA.getfirst(m.expand(r'\1'),''),
	FILE.read())
  print "</body></html>"

form = cgi.FieldStorage()

output(form)
