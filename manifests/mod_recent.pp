# == Class: iptables::mod_recent
#
# This is a wrapper for managing the xt_recent portion of iptables
# settings.
#
# It is mainly meant to be a helper class but can be used alone if
# required.
#
# == Parameters
#
# [*notify_iptables*]
#   Boolean:
#   Default: 'true'
#     Whether or not to notify the iptables server when complete.
#
# [*ip_list_tot*]
#   Integer:
#   Default: 200
#     The number of addresses remembered per table. This effectively
#     becomes the maximum size of your block list. Be aware that more
#     addresses means more load on your system.
#
# [*ip_pkt_list_tot*]
#   Integer:
#   Default: 20
#     The number of packets per address remembered.
#
# [*ip_list_hash_size*]
#   Integer:
#   Default: 0
#     Hash table size. 0 means to calculate it based on ip_list_tot,
#     default: 512.
#
# [*ip_list_perms*]
#   Integer:
#   Default: 0640
#     Permissions for /proc/net/xt_recent/* files.
#
# [*ip_list_uid*]
#   Integer:
#   Default: 0
#     Numerical UID for ownership of /proc/net/xt_recent/* files.
#
# [*ip_list_gid*]
#   Integer:
#   Default: 0
#     Numerical GID for ownership of /proc/net/xt_recent/* files.
#
# == Authors
#
# Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::mod_recent (
  $notify_iptables = hiera('iptables::xt_recent::notify_iptables',true),
  $ip_list_tot = hiera('iptables::xt_recent::ip_list_tot','200'),
  $ip_pkt_list_tot = hiera('iptables::xt_recent::ip_pkt_list_tot','20'),
  $ip_list_hash_size = hiera('iptables::xt_recent::ip_list_hash_size','0'),
  $ip_list_perms = hiera('iptables::xt_recent::ip_list_perms','0640'),
  $ip_list_uid = hiera('iptables::xt_recent::ip_list_uid','0'),
  $ip_list_gid = hiera('iptables::xt_recent::ip_list_gid','0')
) {

  file { '/etc/modprobe.d/xt_recent.conf':
    ensure  => 'file',
    owner   => 'root',
    group   => 'root',
    mode    => '0640',
    content => "options xt_recent ip_list_tot=${ip_list_tot} ip_pkt_list_tot=${ip_pkt_list_tot} ip_list_hash_size=${ip_list_hash_size} ip_list_perms=${ip_list_perms} ip_list_uid=${ip_list_uid} ip_list_gid=${ip_list_gid}"
  }

  xt_recent { '/sys/module/xt_recent/parameters':
    ip_list_tot       => $ip_list_tot,
    ip_pkt_list_tot   => $ip_pkt_list_tot,
    ip_list_hash_size => $ip_list_hash_size,
    ip_list_perms     => $ip_list_perms,
    ip_list_uid       => $ip_list_uid,
    ip_list_gid       => $ip_list_gid
  }

  if str2bool($notify_iptables) {
    Xt_recent['/sys/module/xt_recent/parameters'] ~> Service['iptables']
  }
}
