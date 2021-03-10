# Manage the IPTables and IP6Tables services
#
# This also installs fallback startup scripts that come into play should the
# regular processes fail to start due to a race condition with DNS.
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

  if $enable != 'ignore' {
    if $enable {
      $_ensure = 'running'
      $_enable = true
    }
    else {
      $_ensure = 'stopped'
      $_enable = false
    }

    file { '/etc/init.d/iptables':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => file("${module_name}/iptables"),
      seltype => 'iptables_initrc_exec_t'
    }

    # --------------------------------------------------
    # Set the iptables startup script to fail safe.
    #
    file { '/etc/init.d/iptables-retry':
      ensure  => 'file',
      owner   => 'root',
      group   => 'root',
      mode    => '0744',
      content => file("${module_name}/iptables-retry"),
      seltype => 'iptables_initrc_exec_t'
    }

    service { 'iptables':
      ensure     => $_ensure,
      enable     => $_enable,
      hasrestart => false,
      restart    => '/sbin/iptables-restore /etc/sysconfig/iptables || ( /sbin/iptables-restore /etc/sysconfig/iptables.bak && exit 3 )',
      hasstatus  => true,
      require    => File['/etc/init.d/iptables'],
      provider   => 'redhat'
    }

    service { 'iptables-retry':
      enable   => $_enable,
      require  => File['/etc/init.d/iptables-retry'],
      provider => 'redhat'
    }

    if $ipv6 and $facts['ipv6_enabled'] {
      file { '/etc/init.d/ip6tables':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0755',
        seltype => 'iptables_initrc_exec_t',
        content => file("${module_name}/ip6tables")
      }

      file { '/etc/init.d/ip6tables-retry':
        ensure  => 'file',
        owner   => 'root',
        group   => 'root',
        mode    => '0744',
        seltype => 'iptables_initrc_exec_t',
        content => file("${module_name}/ip6tables-retry")
      }
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
