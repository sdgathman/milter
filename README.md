# milter

This repo has three python milter packages.

## bms
This is the original application that drove the need for pymilter, and then
pydspam, pygossip, pyspf, pydkim.  It is very effective,and used on dozens of
production mail servers.  But it is kind of "hacky", with features added by
busy mail admins without enough thought toward ease of configuration by new
users.  Even if you don't install it, I recommend it as a rich source of
examples of real life use of pymilter and other email related python packages.

The driving principle is authentication and reputation.  For instance, when
banning a domain, you don't just ban the domain, but a given level of
authentication for that domain.  If spam.com is unauthenticated, then banning
spam.com does not block an authenticated email from spam.com - because the spam
may have been forged.  But if the spam email from spam.com that triggers
the ban (or bad reputation) is authenticated, then all emails from that domain
are banned.

It implements per-domain policies and reputation tracking based on SPF 
or DKIM result (example.com:PASS tracks a different reputation than
example.com:NEUTRAL). 

The primary authentication methods are SPF (Sender Policy Framework) and DKIM.  DMARC would be a future enhancement.  Greylisting is also used.

## spfmilter
This is a simple SPF milter that adds Received-SPF, logs, and optionally rejects based on reject with policy configured per MFROM domain.  Use as is, or as a starting point for your own custom milter.

## dkim-milter
This is a simple DKIM milter that signs outgoing mail and adds Authentication-Results, logs, and optionally rejects incoming mail based on local and Author Domain Sender Policy (ADSP).
