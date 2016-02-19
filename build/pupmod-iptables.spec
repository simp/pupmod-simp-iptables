Summary: IPTables Puppet Module
Name: pupmod-iptables
Version: 4.1.0
Release: 15
License: Apache License, Version 2.0
Group: Applications/System
Source: %{name}-%{version}-%{release}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Requires: pupmod-auditd >= 2.0.0-0
Requires: pupmod-common >= 4.0.0-0
Requires: pupmod-simplib >= 1.0.0-0
Requires: pupmod-rsyslog >= 2.0.0-0
Requires: pupmod-simpcat >= 2.0.0-0
Requires: puppet >= 3.3.0
Buildarch: noarch
Requires: simp-bootstrap >= 4.2.0
Provides: pupmod-ip6tables
Obsoletes: pupmod-ip6tables
Obsoletes: pupmod-iptables-test
Requires: pupmod-onyxpoint-compliance_markup

Prefix: %{_sysconfdir}/puppet/environments/simp/modules

%description
This Puppet module provides the capability to configure IPTables rules for your
system.
This interface works for basic IPTables functionality.  Advanced use may require
extending the module to provide additional flexibility.

%prep
%setup -q

%build

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/iptables

dirs='files lib manifests templates'
for dir in $dirs; do
  test -d $dir && cp -r $dir %{buildroot}/%{prefix}/iptables
done

mkdir -p %{buildroot}/usr/share/simp/tests/modules/iptables

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

mkdir -p %{buildroot}/%{prefix}/iptables

%files
%defattr(0640,root,puppet,0750)
%{prefix}/iptables

%post
#!/bin/sh

if [ -d %{prefix}/iptables/plugins ]; then
  /bin/mv %{prefix}/iptables/plugins %{prefix}/iptables/plugins.bak
fi

if [ $1 -gt 1 ]; then
  # We don't want these facts hanging around any longer.
  for file in %{prefix}/iptables/lib/facter/ip*tables_requires_restart.rb; do
    if [ -f $file ]; then
      rm $file
    fi
  done
fi

%postun
# Post uninstall stuff

%changelog
* Fri Feb 19 2016 Ralph Wright <ralph.wright@onyxpoint.com> - 4.1.0-15
- Added compliance function support

* Mon Nov 09 2015 Chris Tessmer <chris.tessmer@onypoint.com> - 4.1.0-14
- migration to simplib and simpcat (lib/ only)

* Mon Jul 27 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-13
- Added an iptables::prevent_localhost_spoofing class to handle IPv6 spoofed
  communication.

* Wed Jul 08 2015 Chris Tessmer <chris.tessmer@onyxpoint.com> - 4.1.0-12
- Updated iptables::disable's default to look up 'use_iptables' from hiera.
- Fixed iptables::disable to disable management of IPv4 rules.

* Mon Apr 27 2015 Michael Riddle <mriddle@onyxpoint.com> - 4.1.0-11
- Implemented a workaround for ports being read in as valid ipv6 addresses on
  iptables lines that don't contain any ipaddress. Any iptables lines
  containing a port with no ipaddress would only validate as an ipv6 rule.

* Thu Apr 02 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-10
- Fixed DNS resolution in the IPTables provider. Unfortunately, this never
  actually worked as implemented.

* Fri Jan 16 2015 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-9
- Changed puppet-server requirement to puppet

* Tue Aug 05 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-8
- Changed all top-scope class variable calls to actual global
  variables. This isn't great, but there isn't an elegant way to do
  this inside Puppet right now.
- Update to fix the scenario where the /etc/sysconfig/ip*tables files
  don't exist.
- Fixed a typo where the ip6tables-retry script was really calling
  iptables.

* Tue Jul 15 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-7
- Added CentOS as a supported OS as part of CentOS 7 upgrade.

* Thu Jun 26 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-6
- Provide for RHEL7 compatiblity.
- Added an iptables::disable option that will disable our IPTables
  enforcement by way of telling optimize to effectively noop.
- Rewrote most of the IPTables native type to be more maintainable.
- Added a new option iptables::authoritative which, when set, ties
  iptables_optimize to the iptables service. When not set, optimize
  will simply do what it can on the chains that it knows about. This
  is new and may need a bit more work on some edge cases.

* Sun Jun 22 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-5
- Removed MD5 file checksums for FIPS compliance.

* Tue Apr 29 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-4
- Updated the optimize code to ignore matches in both chains and jumps.

* Tue Apr 15 2014 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-4
- Ensure that DNS lookups are sorted so that iptables does not continually restart.
- Moved the default rules out of sec and into iptables::base_rules.
- Updated the iptables class to call out to base_rules and scanblock based on
  parameters.

* Thu Feb 13 2014 Kendall Moore <kmoore@keywcorp.com> - 4.1.0-3
- Updated all string booleans to native booleans in manifests and templates.

* Wed Dec 11 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-2
- Updated the rule comparison code in iptables_rule to properly compare the new
  and old rules.
- Properly handle blank lines in the /etc/sysconfig/ip*tables files.
- Fixed the providers to properly handle the case where /etc/sysconfig/iptables
  is absent and/or the commands are at alternate paths.

* Thu Nov 21 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.1.0-1
- Made several changes to the iptables_rule custom type to:
  * Now resolves all hostnames in the rules by default. This can be
    disabled but may cause issues with the autodiscovery between ipv4
    and ipv6 rules.
  * Handle blank lines
  * Account for all table declarations
  * Compare while ignoring the table declarations since those are
    allowed to vary.
  * Ensure that the -A header is not prepended to a rule if it already
    has a header value.
  * Ensure that no rules attempt to be added if they belong to a table
    that is not valid for the given ip*tables type.

* Tue Nov 19 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.1-1
- Fixed an issue in iptables_optimize where a situation could arize
  that would cause the table definitions to not be properly loaded and
  the iptables reload to fail.

* Thu Oct 10 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.1-0
- Removed all calls to the Puppet FileLocking classes which get removed in
  later versions of Puppet.
- Added an iptables::scanblock class which will work to
  semi-permanently block any IP address that is prodding your host.
  This is mainly intended for Internet facing hosts.
- The IPTables module custom types were almost completely rewritten.
- The ip*tables_requires_restart facts are gone and you can now pass
  an array of regular expressions to the 'ignore' variable of the
  iptables class and have it ignore running rules with targets
  matching any of the expressions when deciding to restart ip*tables.

* Fri Oct 04 2013 Nick Markowski <nmarkowski@keywcorp.com> - 4.0.0-1
- Updated template to reference instance variables with @

* Wed Jul 31 2013 Trevor Vaughan <tvaughan@onyxpoint.com> - 4.0.0-0
- CRIT: There was a severe bug in allow_all_services.erb that would
  make any call to iptables::add_all_listen open IPTables to all
  hosts. This has been corrected.
- Updated the ip*tables_requires_restart facts to only select on the
  -j options no matter what order they are in.
- Added a call to 'validate_net_list' to all iptables defines so that
  incorrect client_nets arrays fail hard.

* Tue Jan 08 2013 Maintenance
2.1.0-6
- Added two new facts: iptables_requires_restart and ip6tables_requires_restart
  that replace the ip(6)?tables_running and ip(6)?tables_saved facts. The old
  facts simply were not accurate enough for complex situations.
- Update to fix the ability of the iptables rule mechanisms to handle rules
  with over 15 ports.
- Updated to require pupmod-common >= 2.1.1-2 so that upgrading an old
  system works properly.

* Fri Oct 19 2012 Maintenance
2.1.0-5
- Removed one line in the iptables_rule type that caused the type to fail if
  ipv6 wasn't enabled on the target system.

* Tue Sep 18 2012 Maintenance
2.1.0-4
- Updated all references of /etc/modprobe.conf to /etc/modprobe.d/00_simp_blacklist.conf
  as modprobe.conf is now deprecated.

* Fri Aug 17 2012 Maintenance
2.1.0-3
- Moved all dynamic resource creation and checking to 'finish' instead of
  'initialize' in the custom type.

* Tue Jul 24 2012 Maintenance
2.1.0-2
- Fix all instances of 'IPT:' instead of "IPT:"

* Tue Jun 26 2012 Maintenance
2.1.0-1
- Trigger ip6?tables restart when rules change on the host regardless of the
  count.

* Thu Jun 07 2012 Maintenance
2.1.0-0
- Ensure that Arrays in templates are flattened.
- Call facts as instance variables.
- Rewrote the iptables templates to more efficiently handle checking for the
  'any' case.
- Moved mit-tests to /usr/share/simp...
- This is a massive rewrite of the iptables module that adds native
  support for ip6tables as well as some magical rule munging that
  should make life easier.
- The old methods have been kept around for backward compatibliity
  purposes.
- Rules are now also optimized before being written and ip(6)tables
  will try to fall back to the previous configuration upon restart.
- This is *not* the Puppet Labs module since that one a) doesn't let
  you add artibrary rules and b) modifies rules on the fly which
  turned out to be quite dangerous at times. This is more of an
  all-or-nothing approach.
- More will be added to the native type as time allows.

* Fri Mar 02 2012 Maintenance
2.0.0-6
- Added a startup script, iptables-retry to try and restart iptables after
  networking starts just in case a rule was added with an fqdn.
- Updated the iptables startup script to the latest version.
- Reformatted all code to meet Puppet Labs' guidance.
- Improved test stubs.
- Added a check in the custom facts to not call iptables if service iptables
  status doesn't return anything.

* Mon Dec 26 2011 Maintenance
2.0.0-5
- Updated the spec file to not require a separate file list.
- Scoped all of the top level variables.

* Mon Dec 05 2011 Maintenance
2.0.0-4
- No longer print the status messages when nothing needs to happen. These can
  be enabled using the $class_debug variable.

* Mon Oct 10 2011 Maintenance
2.0.0-3
- Updated to put quotes around everything that need it in a comparison
  statement so that puppet > 2.5 doesn't explode with an undef error.

* Mon Sep 12 2011 Maintenance
2.0.0-2
- Ensure that the iptables_running fact does not do DNS lookups.

* Mon Apr 18 2011 Maintenance - 2.0.0-1
- Changed puppet://$puppet_server/ to puppet:///
- Updated to use concat_build and concat_fragment types.

* Tue Jan 11 2011 Maintenance
2.0.0-0
- Refactored for SIMP-2.0.0-alpha release

* Tue Oct 26 2010 Maintenance - 1-1
- Converting all spec files to check for directories prior to copy.

* Fri May 21 2010 Maintenance
1.0-0
- Doc update and code refactor

* Fri May 07 2010 Maintenance
0.1-20
- Added a fact, iptables_running that returns the number of rules in the
  running iptables.
- Added a fact, iptables_saved that returns the number of rules in the saved
  iptables rule set.
- Added a check to see if the running IPTables ruleset has fewer rules than the
  specified IPTables ruleset. If it does, have IPTables reload.

* Sat Feb 13 2010 Maintenance
0.1-19
- Moved the ESTABLISHED/RELATED rule to the top of the stack.

* Thu Jan 28 2010 Maintenance
0.1-18
- The IPTables service now uses iptables-restore instead of 'service iptables
  restart' to restart iptables. This means that no state will be lost due to
  spurious iptables restarts.

* Mon Nov 02 2009 Maintenance
0.1-17
- Added the ability to have custom comments above each entry.
- Now remove any subsequent duplicate entries comments will, of course, cause
  problems with this.
