import os
import sys
from distutils.core import setup, Extension

# NOTE: importing Milter to obtain version fails when milter.so not built
setup(name = "milter", version = '0.8.14',
	description="Anti-forgery, reputation tracking, anti-spam milter",
	long_description="""\
This is a milter application based on pymilter.  It implements per-domain
policies and reputation tracking based on SPF result (example.com:PASS tracks a
different reputation than example.com:NEUTRAL).  It has too many features.  A
simple SPF checking milter with policy in sendmail access file based on domain
and SPF result is also included.
""",
	author="Stuart Gathman",
	author_email="stuart@bmsi.com",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@bmsi.com",
	license="GPL",
	url="http://www.bmsi.com/python/milter.html",
	keywords = ['sendmail','milter'],
	classifiers = [
	  'Development Status :: 5 - Production/Stable',
	  'Environment :: No Input/Output (Daemon)',
	  'Intended Audience :: System Administrators',
	  'License :: OSI Approved :: GNU General Public License (GPL)',
	  'Natural Language :: English',
	  'Operating System :: POSIX',
	  'Programming Language :: Python',
	  'Topic :: Communications :: Email :: Mail Transport Agents',
	  'Topic :: Communications :: Email :: Filters'
	]
)
