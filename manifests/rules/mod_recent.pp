# A wrapper for managing the xt_recent portion of iptables settings
#
# It is mainly meant to be a helper class but can be used alone if
# required.
#
# @param notify_iptables
#   Notify the IPTables service when complete
#
# @param ip_list_tot
#   The number of addresses remembered per table
#
#   *This effectively becomes the maximum size of your ban list
#   * Be aware that more addresses means more load on your system
#
# @param ip_pkt_list_tot
#   The number of packets per address remembered
#
# @param ip_list_hash_size
#   Hash table size
#
#   * 0 means to calculate it based on ``ip_list_tot``
#
# @param ip_list_perms
#   Permissions for ``/proc/net/xt_recent/*`` files
#
# @param ip_list_uid
#   Numerical UID for ownership of ``/proc/net/xt_recent/*`` files
#
# @param ip_list_gid
#   Numerical GID for ownership of ``/proc/net/xt_recent/*`` files
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::rules::mod_recent (
  Boolean    $notify_iptables   = true,
  Integer[0] $ip_list_tot       = 200,
  Integer[0] $ip_pkt_list_tot   = 20,
  Integer[0] $ip_list_hash_size = 0,
  String     $ip_list_perms     = '0640',
  Integer[0] $ip_list_uid       = 0,
  Integer[0] $ip_list_gid       = 0
){
  file { '/etc/modprobe.d/xt_recent.conf':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    content => "options xt_recent ip_list_tot=${ip_list_tot} ip_pkt_list_tot=${ip_pkt_list_tot} ip_list_hash_size=${ip_list_hash_size} ip_list_perms=${ip_list_perms} ip_list_uid=${ip_list_uid} ip_list_gid=${ip_list_gid}"
  }

  ### This is here due to an issue where changes to
  # /etc/modprobe.d/xt_recent.conf that happen *after* the module is loaded
  # will cause a kernel panic if the buffer sizes are *increased*
  #
  # Comment this section out and run the acceptance tests if you want to see if
  # it has been fixed
  #
  # Presently affects both EL6 and EL7 systems
  exec { 'reload xt_recent':
    command     => '/sbin/rmmod xt_recent ||: && /sbin/modprobe xt_recent ||:',
    refreshonly => true
  }

  Xt_recent['/sys/module/xt_recent/parameters'] -> File['/etc/modprobe.d/xt_recent.conf']
  File['/etc/modprobe.d/xt_recent.conf'] ~> Exec['reload xt_recent']

  ### End workaround for kernel panic

  xt_recent { '/sys/module/xt_recent/parameters':
    ip_list_tot       => $ip_list_tot,
    ip_pkt_list_tot   => $ip_pkt_list_tot,
    ip_list_hash_size => $ip_list_hash_size,
    ip_list_perms     => $ip_list_perms,
    ip_list_uid       => $ip_list_uid,
    ip_list_gid       => $ip_list_gid
  }

  if str2bool($notify_iptables) {
    Xt_recent['/sys/module/xt_recent/parameters'] ~> Class['iptables::service']
  }
}
