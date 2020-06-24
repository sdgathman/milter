import os
import sys
import setuptools

# Use the spec file to install the machinery to run this as a service.
# This setup is just used to register.

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(name = "milter", version = '1.0',
	description="Anti-forgery, reputation tracking, anti-spam milter",
	long_description=long_description,
	author="Stuart Gathman",
	author_email="stuart@bmsi.com",
	maintainer="Stuart D. Gathman",
	maintainer_email="stuart@bmsi.com",
	license="GPL",
	url="http://pythonhosted.org/milter/",
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
