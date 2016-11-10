# == Class: iptables::scanblock
#
# This class provides a method for setting up an iptables electric
# fence. Any host that makes it past all of your allow rules will be
# added to the ban list.
#
# If you enable this, be sure to enable your IPTables rules prior to
# connecting with a client or you're likely to completely deny your
# internal hosts.
#
# NOTE: Changing *any* of the 'ip_*' variables will cause the iptables
# service to be triggered. This is because the variables cannot take
# effect until the iptables rules are reset.
#
# === Management ===
#
# Details on managing xt_recent can be found in iptables(8). The
# following are just some useful commands.
#
# [*Add address to list*]
#   echo +addr >/proc/net/xt_recent/LIST_NAME
#
# [*Remove address from list*]
#   echo -addr >/proc/net/xt_recent/LIST_NAME
#
# [*Remove all address from list*]
#   echo / >/proc/net/xt_recent/LIST_NAME
#
# The work is based on the work detailed in
# http://www.thatsgeeky.com/2011/01/limiting-brute-force-attacks-with-iptables/
#
# == Parameters
#
# [*enable*]
#   Boolean:
#   Default: 'true'
#     Whether or not to enable this class.
#
# [*seconds*]
#   Integer:
#   Default: 60
#     Connections from attackers must happen within this number of
#     seconds to be considered an attack. Directly relates to hitcount
#     to log and block attackers.
#
# [*hitcount*]
#   Integer:
#   Default: 2
#     The number of hits that must happen within 'seconds' to be
#     considered an account.
#
# [*set_rttl*]
#   Boolean:
#   Default: false
#     Set this if you worry about having external parties DoS your
#     system by spoofing their IP addresses.
#
# [*update_interval*]
#   Integer:
#   Default: '3600'
#     Block attackers for this long (in seconds). Connecting systems
#     must not connect for at least this long prior to being allowed
#     to reconnect.
#
# [*logs_per_minute*]
#   Integer:
#   Default: '5'
#     How many logs to send given logs_per_minute connections per
#     minute. This is mainly so that you don't end up overrunning your
#     log services.
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
#     Hash table size. 0 means to calculate it based on ip_list_tot.
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
#   Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::scanblock (
  $enable = hiera('iptables::scanblock::enable',true),
  $seconds = hiera('iptables::scanblock::seconds','60'),
  $hitcount = hiera('iptables::scanblock::hitcount','2'),
  $set_rttl = hiera('iptables::scanblock::set_rttl',false),
  $update_interval = hiera('iptables::scanblock::update_interval','3600'),
  $logs_per_minute = hiera('iptables::scanblock::logs_per_minute','5'),
  $ip_list_tot = hiera('iptables::xt_recent::ip_list_tot','200'),
  $ip_pkt_list_tot = hiera('iptables::xt_recent::ip_pkt_list_tot','20'),
  $ip_list_hash_size = hiera('iptables::xt_recent::ip_list_hash_size','0'),
  $ip_list_perms = hiera('iptables::xt_recent::ip_list_perms','0640'),
  $ip_list_uid = hiera('iptables::xt_recent::ip_list_uid','0'),
  $ip_list_gid = hiera('iptables::xt_recent::ip_list_gid','0')
) {
  validate_bool($enable)
  validate_bool($set_rttl)
  validate_integer($update_interval)
  validate_integer($logs_per_minute)
  validate_integer($seconds)
  validate_integer($hitcount)

  include 'iptables'

  if str2bool($set_rttl) {
    $rttl = '--rttl'
  }
  else {
    $rttl = ''
  }

  if str2bool($enable) {
    iptables_rule{'scanblock':
      order    => '28',
      header   => false,
      apply_to => 'all',
      content  => "-A LOCAL-INPUT -m recent --update --seconds ${update_interval} --name BANNED --rsource -j DROP
-A LOCAL-INPUT -m state --state NEW -j ATTK_CHECK
-A ATTACKED -m limit --limit ${logs_per_minute}/min -j LOG --log-prefix \"IPT: (Rule ATTACKED): \"
-A ATTACKED -m recent --set --name BANNED --rsource -j DROP
-A ATTK_CHECK -m recent --set --name ATTK --rsource
-A ATTK_CHECK -m recent --update --seconds ${seconds} --hitcount ${hitcount} ${rttl} --name ATTK --rsource -j ATTACKED"
    }
  }

  class { 'iptables::mod_recent':
    ip_list_tot       => $ip_list_tot,
    ip_pkt_list_tot   => $ip_pkt_list_tot,
    ip_list_hash_size => $ip_list_hash_size,
    ip_list_perms     => $ip_list_perms,
    ip_list_uid       => $ip_list_uid,
    ip_list_gid       => $ip_list_gid,
    notify_iptables   => true
  }
}
