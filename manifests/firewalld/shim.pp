# These items mimic components in the actual `firewalld` module but set them to
# safer defaults per the usual "authoritative control" idea of SIMP.
#
# Since the `firewalld` module is designed to be Hiera-driven, this was more
# understandable and safer than encapsulating the entire module in the
# `iptables` module directly.
#
# @param enable
#   Activate the firewalld shim capabilties.
#
# @param complete_reload
#   The current firewalld module has the capability to perform a complete reload
#   of firewalld which breaks any existing connections. This is extremely
#   dangerous and this class overrides and disables this capability by default.
#
#   * Set to ``true`` to re-enable this capability.
#
# @param lockdown
#   Set ``firewalld`` in ``lockdown`` mode which disallows manipulation by
#   applications.
#
#   * This makes sense to do by default since puppet is meant to be
#     authoritative on the system.
#
# @param default_zone
#   The 'default zone' to set on the system.
#
#   This is set to ``99_simp`` so that regular, alternative, zone manipulation
#   can occur without interference.
#
#   **IMPORTANT:** If this is set to anything besides ``99_simp``, all rules in
#   this module will **NOT** apply to the default zone! This module is set to
#   only populate ``99_simp`` zone rules.
#
# @param log_denied
#   What types of logs to process for denied packets.
#
#   @see LogDenied in firewalld.conf(5)
#
# @param enable_tidy
#   Enable the ``Tidy`` resources that help keep the system clean from cruft
#
# @param tidy_dirs
#   The directories to target for tidying
#
# @param tidy_prefix
#   The name match to use for tidying files
#
# @param tidy_minutes
#   Number of **minutes** to consider a configuration file 'stale' for the
#   purposes of tidying.
#
class iptables::firewalld::shim (
  Boolean                                              $enable               = true,
  Boolean                                              $complete_reload      = false,
  Boolean                                              $lockdown             = true,
  String[1]                                            $default_zone         = '99_simp',
  Enum['off', 'all','unicast','broadcast','multicast'] $log_denied           = 'unicast',
  Boolean                                              $enable_tidy          = true,
  # lint:ignore:2sp_soft_tabs
  Array[Stdlib::Absolutepath]                          $tidy_dirs            = [
                                                                                 '/etc/firewalld/icmptypes',
                                                                                 '/etc/firewalld/ipsets',
                                                                                 '/etc/firewalld/services'
                                                                               ],
  # lint:endignore
  String[1]                                            $tidy_prefix          = 'simp_',
  Integer[1]                                           $tidy_minutes         = 10,
  Array[Optional[String[1]]]                           $simp_zone_interfaces = [],
  Enum['default', 'ACCEPT', 'REJECT', 'DROP']          $simp_zone_target     = 'DROP'
) {
  if $enable {
    simplib::assert_optional_dependency($module_name, 'puppet/firewalld')

    include firewalld

    Exec { path => '/usr/bin:/bin' }

    unless $complete_reload {
      # This breaks all firewall connections and should never be done unless forced
      Exec <| command == 'firewall-cmd --complete-reload' |> { onlyif => '/bin/false' }
    }

    firewalld_zone { '99_simp':
      ensure           => 'present',
      purge_rich_rules => true,
      purge_services   => true,
      purge_ports      => true,
      interfaces       => $simp_zone_interfaces,
      target           => $simp_zone_target,
      require          => Service['firewalld']
    }

    exec { 'firewalld::set_default_zone':
      command => "firewall-cmd --set-default-zone ${default_zone}",
      unless  => "[ \$(firewall-cmd --get-default-zone) = ${default_zone} ]",
      require => [
        Service['firewalld'],
        Exec['firewalld::reload']
      ]
    }

    if $default_zone == '99_simp' {
      Firewalld_zone['99_simp'] -> Exec['firewalld::set_default_zone']
    }

    ensure_resource('exec', 'firewalld::set_log_denied', {
      'command' => "firewall-cmd --set-log-denied ${log_denied} && firewall-cmd --reload",
      'unless'  => "[ $(firewall-cmd --get-log-denied) = ${log_denied} ]",
      require => [
        Service['firewalld'],
        Exec['firewalld::reload']
      ]
    })

    if $lockdown {
      exec { 'lockdown_firewalld':
        command => 'firewall-cmd --lockdown-on',
        unless  => 'firewall-cmd --query-lockdown',
        require => [
          Service['firewalld'],
          Exec['firewalld::reload']
        ]
      }
    }
    else {
      exec { 'unlock_firewalld':
        command => 'firewall-cmd --lockdown-off',
        onlyif  => 'firewall-cmd --query-lockdown',
        require => [
          Service['firewalld'],
          Exec['firewalld::reload']
        ]
      }
    }

    if $enable_tidy {
      tidy { $tidy_dirs:
        age     => "${tidy_minutes}m",
        backup  => false,
        matches => [$tidy_prefix],
        recurse => true,
        type    => 'mtime'
      }
    }
  }
}
