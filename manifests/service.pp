# Manage the IPTables and IP6Tables services
#
# @param enable
#   Enable IPTables
#
#   * If set to ``false`` with **disable** IPTables completely
#   * If set to ``ignore`` will stop managing IPTables
#
# @param ipv6
#   Also manage IP6Tables
#
class iptables::service (
  $enable = pick(getvar('iptables::enable'),true),
  $ipv6   = pick(getvar('iptables::ipv6'),true)
){
  simplib::assert_metadata($module_name)

  unless $iptables::use_firewalld {
    if $enable != 'ignore' {
      if $enable {
        $_ensure = 'running'
        $_enable = true
      }
      else {
        $_ensure = 'stopped'
        $_enable = false
      }

      service { 'iptables':
        ensure     => $_ensure,
        enable     => $_enable,
        hasrestart => false,
        restart    => '/sbin/iptables-restore /etc/sysconfig/iptables || ( /sbin/iptables-restore /etc/sysconfig/iptables.bak && exit 3 )',
        hasstatus  => true,
        provider   => 'redhat'
      }

      service { 'iptables-retry':
        enable   => $_enable,
        provider => 'redhat'
      }

      if $ipv6 and $facts['ipv6_enabled'] {
        service { 'ip6tables':
          ensure     => $_ensure,
          enable     => $_enable,
          hasrestart => false,
          restart    => '/sbin/ip6tables-restore /etc/sysconfig/ip6tables || ( /sbin/ip6tables-restore /etc/sysconfig/ip6tables.bak && exit 3 )',
          hasstatus  => true,
          require    => File['/etc/init.d/ip6tables'],
          provider   => 'redhat'
        }

        service { 'ip6tables-retry':
          enable   => true,
          require  => File['/etc/init.d/ip6tables-retry'],
          provider => 'redhat'
        }
      }

      # firewalld should be disabled
      service{ 'firewalld':
        ensure => 'stopped',
        enable => false
      }

      exec { 'fully stop firewalld':
        command => 'pkill firewalld',
        onlyif  => 'pgrep firewalld',
        path    => [
          '/bin',
          '/usr/bin'
        ],
        require => Service['firewalld']
      }
    }
  }
}
