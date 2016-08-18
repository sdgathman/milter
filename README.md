# milter
This is the original application that drove the need for pymilter, and then pydspam, pygossip, pyspf, pydkim.  It is very effective, 
and used on dozens of production mail servers.  But it is kind of "hacky", with features added by busy mail admins without 
enough thought of ease of configuration by new users.

The driving principle is authentication and reputation.  For instance, when banning a domain, you don't just ban the domain, but
a given level of authentication for that domain.  If spam.com is unauthenticated, then banning spam.com does not block an 
authenticated email from spam.com - because the spam may have been forged.  But if the spam email from spam.com that triggers
the ban (or bad reputation) is authenticated, then all emails from that domain are banned.

The primary authentication methods are SPF (Sender Policy Framework) and DKIM.  DMARC would be a future enhancement.
