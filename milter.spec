# This spec file contains 2 noarch packages in addition to the pymilter
# module.  To compile all three on 32-bit Intel, use:
# rpmbuild -ba --target=i386,noarch pymilter.spec

%define __python python2.4
%define sysvinit milter.rc
%define libdir %{_libdir}/pymilter

Name: milter
Group: Applications/System
Summary:  BMS spam and reputation milter
Version: 0.8.14
Release: 2%{dist}.py24
Source: milter-%{version}.tar.gz
#Patch: %{name}-%{version}.patch
License: GPLv2+
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-buildroot
BuildArch: noarch
Vendor: Stuart D. Gathman <stuart@bmsi.com>
Url: http://www.bmsi.com/python/milter.html
Requires: %{__python} >= 2.4, pyspf >= 2.0.4, pymilter >= 0.9.3
%ifos Linux
Requires: chkconfig
%endif

%description
A complex but effective spam filtering, SPF checking, greylisting,
and reputation tracking mail application.  It uses pydspam if installed for
bayesian filtering.

%package spf
Group: Applications/System
Summary:  BMS spam and reputation milter
Requires: pyspf >= 2.0.4, pymilter >= 0.9.3
Obsoletes: pymilter-spf < 0.8.10

%description spf
A simple mail filter to add Received-SPF headers and reject forged mail.
Rejection policy is configured via sendmail access file and can be
tailored by domain.

%prep
%setup -q -n milter-%{version}
#patch -p0 -b .bms

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc/mail
mkdir -p $RPM_BUILD_ROOT/var/log/milter/save
mkdir -p $RPM_BUILD_ROOT%{libdir}
cp *.txt $RPM_BUILD_ROOT/var/log/milter
cp -p bms.py spfmilter.py ban2zone.py $RPM_BUILD_ROOT%{libdir}
cp milter.cfg $RPM_BUILD_ROOT/etc/mail/pymilter.cfg
cp spfmilter.cfg $RPM_BUILD_ROOT/etc/mail

# logfile rotation
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
cat >$RPM_BUILD_ROOT/etc/logrotate.d/milter <<'EOF'
/var/log/milter/milter.log {
  copytruncate
  compress
}
/var/log/milter/banned_ips {
  rotate 7
  daily
  copytruncate
}
/var/log/milter/banned_domains {
  rotate 7
  weekly
  copytruncate
}
EOF

# purge saved defanged message copies
mkdir -p $RPM_BUILD_ROOT/etc/cron.daily
%ifos aix4.1
R=
%else
R='-r'
%endif
cat >$RPM_BUILD_ROOT/etc/cron.daily/milter <<'EOF'
#!/bin/sh

find /var/log/milter/save -mtime +7 | xargs $R rm
# work around any memory leaks
/etc/init.d/milter condrestart
EOF
chmod a+x $RPM_BUILD_ROOT/etc/cron.daily/milter

%ifnos aix4.1
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
cp %{sysvinit} $RPM_BUILD_ROOT/etc/rc.d/init.d/milter
cp spfmilter.rc $RPM_BUILD_ROOT/etc/rc.d/init.d/spfmilter
ed $RPM_BUILD_ROOT/etc/rc.d/init.d/milter <<'EOF'
/^python=/
c
python="%{__python}"
.
w
q
EOF
ed $RPM_BUILD_ROOT/etc/rc.d/init.d/spfmilter <<'EOF'
/^python=/
c
python="%{__python}"
.
w
q
EOF
%endif	# aix4.1

mkdir -p $RPM_BUILD_ROOT/usr/share/sendmail-cf/hack
cp -p rhsbl.m4 $RPM_BUILD_ROOT/usr/share/sendmail-cf/hack

%ifos aix4.1
%post
mkssys -s milter -p %{libdir}/start.sh -u 25 -S -n 15 -f 9 -G mail || :

%preun
if [ $1 = 0 ]; then
  rmssys -s milter || :
fi
%else # not aix4.1
%post 
#echo "pythonsock has moved to /var/run/milter, update /etc/mail/sendmail.cf"
/sbin/chkconfig --add milter

%preun 
if [ $1 = 0 ]; then
  /sbin/chkconfig --del milter
fi
%post spf
#echo "pythonsock has moved to /var/run/milter, update /etc/mail/sendmail.cf"
/sbin/chkconfig --add spfmilter

%preun spf
if [ $1 = 0 ]; then
  /sbin/chkconfig --del spfmilter
fi
%endif # aix4.1

%files 
%defattr(-,root,root)
/etc/logrotate.d/milter
/etc/cron.daily/milter
%ifos aix4.1
%defattr(-,smmsp,mail)
%else
/etc/rc.d/init.d/milter
%defattr(-,mail,mail)
%endif
%dir /var/log/milter/save
%{libdir}/bms.py
%{libdir}/ban2zone.py
%config(noreplace) /var/log/milter/strike3.txt
%config(noreplace) /var/log/milter/softfail.txt
%config(noreplace) /var/log/milter/fail.txt
%config(noreplace) /var/log/milter/neutral.txt
%config(noreplace) /var/log/milter/quarantine.txt
%config(noreplace) /var/log/milter/permerror.txt
%config(noreplace) /var/log/milter/temperror.txt
%config(noreplace) /etc/mail/pymilter.cfg
/usr/share/sendmail-cf/hack/rhsbl.m4

%files spf
%defattr(-,root,root)
%{libdir}/spfmilter.py*
%config(noreplace) /etc/mail/spfmilter.cfg
/etc/rc.d/init.d/spfmilter

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Sat Apr 10 2010 Stuart Gathman <stuart@bmsi.com> 0.8.14-2
- Default ip banning off

* Sat Apr 10 2010 Stuart Gathman <stuart@bmsi.com> 0.8.14-1
- ignore zero length keywords - a disastrous typo
- ban generic domains for common subdomains
- allow illegal HELO from internal network for braindead copiers
- don't ban for multiple anonymous MFROM
- trust localhost not to be a zombie - sendmail sends from queue on localhost
- ban domains on best_guess pass

* Fri Aug 28 2009 Stuart Gathman <stuart@bmsi.com> 0.8.13-1
- Default internal_policy off
- Experimental banned domain list
- block DSN from internal connections, except for listed internal MTAs
- BAN policy in access file bans connect IP
- use DATA callback to improve SRS check

* Sun Dec 21 2008 Stuart Gathman <stuart@bmsi.com> 0.8.12-2
- internal_policy

* Mon Nov 24 2008 Stuart Gathman <stuart@bmsi.com> 0.8.12-1
- 2 demerits for HELO after MAIL FROM
- Make initscript use pid file.
- Fix greylist config
- SPF Pass policy

* Sat Oct 11 2008 Stuart Gathman <stuart@bmsi.com> 0.8.11-1
- Support greylisting
- Recognize vacation messages as autoreplies.
- Never ban a trusted relay.
- Missing global reading banned_ips
- ban2zone.py

* Mon Aug 25 2008 Stuart Gathman <stuart@bmsi.com> 0.8.10-1
- log rcpt for SRS rejections
- improved parsing into email and fullname (still 2 self test failures)
- implement no-DSN CBV, reduce full DSNs
- check for porn words in MAIL FROM fullname
- ban IP for too many bad MAIL FROMs or RCPT TOs
- temperror policy in access
- no CBV for whitelisted MAIL FROM except permerror, softfail
- Allow explicitly whitelisted email from banned_users.
- configure gossip TTL

* Mon Sep 24 2007 Stuart Gathman <stuart@bmsi.com> 0.8.9-1
- Use ifarch hack to build milter and milter-spf packages as noarch
- Remove spf dependency from dsn.py, add dns.py

* Fri Jan 05 2007 Stuart Gathman <stuart@bmsi.com> 0.8.8-1
- move AddrCache, parse_addr, iniplist to Milter package
- move parse_header to Milter.utils
- fix plock for missing source and can't change owner/group
- add sample spfmilter.py milter
- private_relay config option
- persist delayed DSN blacklisting
- handle gossip server restart without disabling gossip
- split out pymilter and pymilter-spf packages
- move milter apps to /usr/lib/pymilter

* Sat Nov 04 2006 Stuart Gathman <stuart@bmsi.com> 0.8.7-1
- More lame bounce heuristics
- SPF moved to pyspf RPM
- wiretap archive option
- Do plain CBV if missing template
- SMTP AUTH policy in access

* Tue May 23 2006 Stuart Gathman <stuart@bmsi.com> 0.8.6-2
- Support CBV timeout
- Support fail template, headers in templates
- Create GOSSiP record only when connection will procede to DATA.
- More SPF lax heuristics
- Don't require SPF pass for white/black listing mail from trusted relay.
- Support localpart wildcard for white and black lists.

* Thu Feb 23 2006 Stuart Gathman <stuart@bmsi.com> 0.8.6-1
- Delay reject of unsigned RCPT for postmaster and abuse only
- Fix dsn reporting of hard permerror
- Resolve FIXME for wrap_close in miltermodule.c
- Add Message-ID to DSNs
- Use signed Message-ID in delayed reject to blacklist senders
- Auto-train via blacklist and auto-whitelist
- Don't check userlist for signed MFROM
- Accept but skip DSPAM and training for whitelisted senders without SPF PASS
- Report GC stats 
- Support CIDR matching for IP lists
- Support pysrs sign feature
- Support localpart specific SPF policy in access file

* Thu Dec 29 2005 Stuart Gathman <stuart@bmsi.com> 0.8.5-1
- Simple trusted_forwarder implementation.
- Fix access_file neutral policy
- Move Received-SPF header to beginning of headers
- Supply keyword info for all results in Received-SPF header.
- Move guessed SPF result to separate header
- Activate smfi_insheader only when SMFIR_INSHEADER defined
- Handle NULL MX in spf.py
- in-process GOSSiP server support (to be extended later)
- Expire CBV cache and renew auto-whitelist entries

* Fri Oct 21 2005 Stuart Gathman <stuart@bmsi.com> 0.8.4-2
- Don't supply sender when MFROM is subdomain of header from/sender.
- Don't send quarantine DSN for DSNs
- Skip dspam for replies/DSNs to signed MFROM

* Thu Oct 20 2005 Stuart Gathman <stuart@bmsi.com> 0.8.4-1
- Fix SPF policy via sendmail access map (case insensitive keys).
- Auto whitelist senders, train screener on whitelisted messages
- Optional idx parameter to addheader to invoke smfi_insheader
- Activate progress when SMFIR_PROGRESS defined

* Wed Oct 12 2005 Stuart Gathman <stuart@bmsi.com> 0.8.3-1
- Keep screened honeypot mail, but optionally discard honeypot only mail.
- spf_accept_fail option for braindead SPF senders (treats fail like softfail)
- Consider SMTP AUTH connections internal.
- Send DSN for SPF errors corrected by extended processing.
- Send DSN before SCREENED mail is quarantined
- Option to set SPF policy via sendmail access map.
- Option to supply Sender header from MAIL FROM when missing.
- Use logging package to keep log lines atomic.

* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-4
- Limit each CNAME chain independently like PTR and MX

* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-3
- Limit CNAME lookups (regression)

* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-2
- Handle corrupt ZIP attachments

* Fri Jul 15 2005 Stuart Gathman <stuart@bmsi.com> 0.8.2-1
- Strict processing limits per SPF RFC
- Fixed several parsing bugs under RFC 
- Support official IANA SPF record (type99)
- Honeypot support (requires pydspam-1.1.9)
- Extended SPF processing results beyond strict RFC limits
- Support original SES for local bounce protection (requires pysrs-0.30.10)
- Callback exception processing option in milter module

* Thu Jun 16 2005 Stuart Gathman <stuart@bmsi.com> 0.8.1-1
- Fix zip in zip loop in mime.py
- Fix HeaderParseError in bms.py header callback
- Check internal_domains for outgoing mail
- Fix inconsistent results from send_dsn

* Mon Jun 06 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-3
- properly log pydspam exceptions

* Sat Jun 04 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-2
- Include default softfail, strike3 templates

* Wed May 25 2005 Stuart Gathman <stuart@bmsi.com> 0.8.0-1
- Move Milter module to subpackage.
- DSN support for Three strikes rule and SPF SOFTFAIL
- Move /*mime*/ and dynip to Milter subpackage
- Fix SPF unknown mechanism list not cleared
- Make banned extensions configurable.
- Option to scan zipfiles for bad extensions.

* Tue Feb 08 2005 Stuart Gathman <stuart@bmsi.com> 0.7.3-1.EL3
- Support EL3 and Python2.4 (some scanning/defang support broken)

* Mon Aug 30 2004 Stuart Gathman <stuart@bmsi.com> 0.7.2-1
- Fix various SPF bugs
- Recognize dynamic PTR names, and don't count them as authentication.
- Three strikes and yer out rule.
- Block softfail by default unless valid PTR or HELO
- Return unknown for null mechanism
- Return unknown for invalid ip address in mechanism
- Try best guess on HELO also
- Expand setreply for common errors
- make rhsbl.m4 hack available for sendmail.mc

* Sun Aug 22 2004 Stuart Gathman <stuart@bmsi.com> 0.7.1-1
- Handle modifying mislabeled multipart messages without an exception
- Support setbacklog, setmlreply
- allow multi-recipient CBV
- return TEMPFAIL for SPF softfail

* Fri Jul 23 2004 Stuart Gathman <stuart@bmsi.com> 0.7.0-1
- SPF check hello name
- Move pythonsock to /var/run/milter
- Move milter.cfg to /etc/mail/pymilter.cfg
- Check M$ style XML CID records by converting to SPF
- Recognize, but never match ip6 until we properly support it.
- Option to reject when no PTR and no SPF

* Fri Apr 09 2004 Stuart Gathman <stuart@bmsi.com> 0.6.9-1
- Validate spf.py against test suite, and add Received-SPF support to spf.py
- Support best_guess for SPF
- Reject numeric hello names
- Preserve case of local part in sender
- Make libmilter timeout a config option
- Fix setup.py to work with python < 2.2.3

* Tue Apr 06 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-3
- Reject invalid SRS immediately for benefit of callback verifiers
- Fix include bug in spf.py

* Tue Apr 06 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-2
- Bug in check_header

* Mon Apr 05 2004 Stuart Gathman <stuart@bmsi.com> 0.6.8-1
- Don't report spoofed unless rcpt looks like SRS
- Check for bounce with multiple rcpts
- Make dspam see Received-SPF headers
- Make sysv init work with RH9

* Thu Mar 25 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-3
- Forgot to make spf_reject_neutral global in bms.py

* Wed Mar 24 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-2
- Defang message/rfc822 content_type with boundary 
- Support SPF delegation
- Reject neutral SPF result for selected domains

* Tue Mar 23 2004 Stuart Gathman <stuart@bmsi.com> 0.6.7-1
- SRS forgery check.  Detect thread resource starvation.
- Properly remove local socket with explicit type.
- Decode obfuscated subject headers.

* Wed Mar 11 2004 Stuart Gathman <stuart@bmsi.com> 0.6.6-2
- init script bug with python2.3

* Wed Mar 10 2004 Stuart Gathman <stuart@bmsi.com> 0.6.6-1
- SPF checking, hello blacklist

* Mon Mar 08 2004 Stuart Gathman <stuart@bmsi.com> 0.6.5-2
- memory leak in envfrom and envrcpt

* Mon Mar 01 2004 Stuart Gathman <stuart@bmsi.com> 0.6.5-1
- progress notification
- memory leak in connect
- trusted relay

* Thu Feb 19 2004 Stuart Gathman <stuart@bmsi.com> 0.6.4-2
- smart alias wildcard patch, compile for sendmail-8.12

* Thu Dec 04 2003 Stuart Gathman <stuart@bmsi.com> 0.6.4-1
- many fixes for dspam support

* Wed Oct 22 2003 Stuart Gathman <stuart@bmsi.com> 0.6.3
- dspam SCREEN feature
- streamline dspam false positive handling

* Mon Sep 01 2003 Stuart Gathman <stuart@bmsi.com> 0.6.1
- Full dspam support added

* Mon Aug 26 2003 Stuart Gathman <stuart@bmsi.com>
- Use New email module

* Fri Jun 27 2003 Stuart Gathman <stuart@bmsi.com>
- Add dspam module
