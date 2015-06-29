# == Class: iptables
#
# This sets the system up in a way that will maximally utilize the iptables
# native types.
#
# == Parameters
#
# [*authoritative*]
# Type: Boolean
# Default: true
#   If true, only iptables rules set by Puppet may be present on the
#   system. Otherwise, only manage the *chains* that Puppet is
#   managing.
#
#   Be *extremely* careful with this option. If you don't match all of
#   your rules that you want left around, but you also don't have
#   something to clean up the various tables, you will get continuous
#   warnings that IPTables rules are being optimized.
#
# [*class_debug*]
# Type: Boolean
# Default: false
#   If true, the system will print messages regarding rule comparisons.
#
# [*optimize_rules*]
# Type: Boolean
# Default: true
#   If true, the inbuilt iptables rule optimizer will be run to collapse the
#   rules down to as small as is reasonably possible without reordering. IPsets
#   will be used eventually.
#
# [*ignore*]
# Type: Array
# Default: []
#   Set this to an Array of regular expressions that you would like to match in
#   order to preserve running rules. This modifies the behavior of the optimize
#   type.  Do not include the beginning and ending '/' but do include an end or
#   beginning of word marker if appropriate.
#
# [*enable_default_rules*]
# Type: Boolean
# Default: true
#   If true, enable the usual set of default deny rules that you would expect
#   to see on most systems.
#
#   This uses the following expectations of rule ordering (not enforced):
#     * 1 -> ESTABLISHED,RELATED rules.
#     * 2-5 -> Standard ACCEPT/DENY rules.
#     * 6-10 -> Jumps to other rule sets.
#     * 11-20 -> Pure accept rules.
#     * 22-30 -> Logging and rejection rules.
#
# [*enable_scanblock*]
# Type: Boolean
# Default: false
#   If true, enable a technique for setting up port-based triggers that will
#   block anyone connecting to the system for an hour after connection to a
#   forbidden port.
#
# [*disable*]
# Type: Boolean
# Default: false
#   If true, disable iptables management completely. The build will
#   still happen but nothing will be enforced.
#
# == Authors:
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#   * Chris Tessmer  <chris.tessmer@onyxpoint.com>
#
class iptables (
  $authoritative        = true,
  $class_debug          = false,
  $optimize_rules       = true,
  $ignore               = [],
  $enable_default_rules = true,
  $enable_scanblock     = false,
  $disable              = !hiera( 'use_iptables', true )
) {
  validate_bool($authoritative)
  validate_bool($class_debug)
  validate_bool($optimize_rules)
  validate_array($ignore)
  validate_bool($enable_default_rules)
  validate_bool($enable_scanblock)
  validate_bool($disable)

  if $enable_default_rules { include 'iptables::base_rules' }
  if $enable_scanblock { include 'iptables::scanblock' }

  # IPV4-only stuff
  file { '/etc/init.d/iptables':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0744',
    source  => 'puppet:///modules/iptables/iptables',
    require => Package['iptables']
  }

  # --------------------------------------------------
  # Set the iptables startup script to fail safe.
  #
  file { '/etc/init.d/iptables-retry':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0744',
    source  => 'puppet:///modules/iptables/iptables-retry',
    require => Package['iptables']
  }

  file { '/etc/sysconfig/iptables':
    ensure  => 'present',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    audit   => 'content',
    require => [
      Package['iptables'],
      Iptables_optimize['/etc/sysconfig/iptables']
    ]
  }

  package { 'iptables': ensure => 'latest' }

  # This has magic voodoo from the optimize segment.
  service { 'iptables':
    ensure     => 'running',
    enable     => true,
    hasrestart => false,
    restart    => '/sbin/iptables-restore /etc/sysconfig/iptables || ( /sbin/iptables-restore /etc/sysconfig/iptables.bak && exit 3 )',
    hasstatus  => true,
    require    => [
      File['/etc/init.d/iptables'],
      Package['iptables']
    ]
  }

  service { 'iptables-retry':
    enable  => true,
    require => [
      File['/etc/init.d/iptables-retry'],
      Package['iptables']
    ]
  }

  if $::ipv6_enabled {

    # IPV6-only stuff
    file { '/etc/init.d/ip6tables':
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0744',
      source => 'puppet:///modules/iptables/ip6tables'
    }

    file { '/etc/init.d/ip6tables-retry':
      ensure => 'file',
      owner  => 'root',
      group  => 'root',
      mode   => '0744',
      source => 'puppet:///modules/iptables/ip6tables-retry'
    }

    file { '/etc/sysconfig/ip6tables':
      ensure  => 'present',
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      audit   => 'content',
      require => [
        Ip6tables_optimize['/etc/sysconfig/ip6tables']
      ]
    }

    # This has magic voodoo from the optimize segment.
    service { 'ip6tables':
      ensure     => 'running',
      enable     => true,
      hasrestart => false,
      restart    => '/sbin/ip6tables-restore /etc/sysconfig/ip6tables || ( /sbin/ip6tables-restore /etc/sysconfig/ip6tables.bak && exit 3 )',
      hasstatus  => true,
      require    => File['/etc/init.d/ip6tables'],
      subscribe  => Ip6tables_optimize['/etc/sysconfig/ip6tables']
    }

    service { 'ip6tables-retry':
      enable  => true,
      require => File['/etc/init.d/ip6tables-retry']
    }

    # A rule optimizer (required)
    ip6tables_optimize { '/etc/sysconfig/ip6tables':
      optimize => $optimize_rules,
      ignore   => $ignore,
      disable  => $disable
    }

    if $authoritative {
      Ip6tables_optimize['/etc/sysconfig/ip6tables'] ~> Service['ip6tables']
    }

    case $::operatingsystem {
      'RedHat','CentOS': {
        if $::operatingsystemmajrelease > '6' {
          Package['iptables'] -> File['/etc/init.d/ip6tables']
          Package['iptables'] -> File['/etc/init.d/ip6tables-retry']
          Package['iptables'] -> File['/etc/sysconfig/ip6tables']
          Package['iptables'] -> Ip6tables_optimize['/etc/sysconfig/ip6tables']
        }
        else {
          package { 'iptables-ipv6': ensure => 'latest' }
          Package['iptables-ipv6'] -> File['/etc/init.d/ip6tables']
          Package['iptables-ipv6'] -> File['/etc/init.d/ip6tables-retry']
          Package['iptables-ipv6'] -> File['/etc/sysconfig/ip6tables']
          Package['iptables-ipv6'] -> Ip6tables_optimize['/etc/sysconfig/ip6tables']
        }
      }
      default: {
        fail("$::operatingsystem is not yet supported by $module_name")
      }
    }
  }


  # firewalld must be disabled on EL7+
  case $::operatingsystem {
    'RedHat','CentOS': {
      if $::operatingsystemmajrelease > '6' {
        service{ 'firewalld':
          enable => false,
          ensure => 'stopped',
        } -> Service['iptables']
      }
    }
    default: {
      fail("$::operatingsystem is not yet supported by $module_name")
    }
  }


  # A rule optimizer (required)
  iptables_optimize { '/etc/sysconfig/iptables':
    optimize => $optimize_rules,
    ignore   => $ignore,
    disable  => $disable
  }

  if $authoritative {
    Iptables_optimize['/etc/sysconfig/iptables'] ~> Service['iptables']
  }
}
