# Provide a method for setting up an iptables electric fence
#
# Any host that makes it past all of your allow rules will be
# added to the ban list.
#
# ------------------------------------------------------------------------
#
# > **WARNING**
# >
# > If you enable this, be sure to enable your IPTables rules prior to
# > connecting with a client or you're likely to **completely deny** your
# > internal hosts.
# >
# > **WARNING**
#
# ------------------------------------------------------------------------
#
# **NOTE:** Changing **any** of the ``ip_*`` variables will cause the iptables
# service to be triggered. This is because the variables cannot take
# effect until the iptables rules are reset.
#
# ## Management
#
# Details on managing xt_recent can be found in ``iptables(8)``. The following
# are just some useful commands.
#
# * Add address to list
#   ``echo +addr >/proc/net/xt_recent/LIST_NAME``
#
# * Remove address from list
#   ``echo -addr >/proc/net/xt_recent/LIST_NAME``
#
# * Remove all address from list
#   ``echo / >/proc/net/xt_recent/LIST_NAME``
#
# @see http://www.thatsgeeky.com/2011/01/limiting-brute-force-attacks-with-iptables/ Limiting Brute Force Attacks with IPTables
#
# @param enable
#   Enable or disable scan blocking
#
# @param seconds
#   Connections from attackers must happen within this number of seconds to be
#   considered an attack
#
#   * Directly relates to hitcount to log and block attackers
#
# @param hitcount
#   The number of hits that must happen within 'seconds' to be considered an
#   attack
#
# @param set_rttl
#   Set this if you worry about having external parties DoS your system by
#   spoofing their IP addresses
#
# @param update_interval
#   Block attackers for this long (in seconds)
#
#   * Connecting systems must not connect for at least this long prior to being
#     allowed to reconnect
#
# @param logs_per_minute
#   How many logs to send given logs_per_minute connections per minute
#
#   * This is mainly so that you don't end up overrunning your log services
#
# @param ip_list_tot
#   The number of addresses remembered per table
#
#   * This effectively becomes the maximum size of your block list
#   * **NOTE:** Be aware that more addresses means more load on your system
#
# @param ip_pkt_list_tot
#   The number of packets per address remembered
#
# @param ip_list_hash_size
#   Hash table size
#
#   * ``0`` means to calculate it based on ``ip_list_tot``
#
# @param ip_list_perms
#   Permissions for ``/proc/net/xt_recent/*`` files
#
# @param ip_list_uid
#   Numerical ``UID`` for ownership of ``/proc/net/xt_recent/*`` files
#
# @param ip_list_gid
#   Numerical ``GID`` for ownership of ``/proc/net/xt_recent/*`` files
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::rules::scanblock (
  Boolean    $enable            = true,
  Integer[0] $seconds           = 60,
  Integer[0] $hitcount          = 2,
  Boolean    $set_rttl          = false,
  Integer[0] $update_interval   = 3600,
  Integer[0] $logs_per_minute   = 5,
  Integer[0] $ip_list_tot       = 200,
  Integer[0] $ip_pkt_list_tot   = 20,
  Integer[0] $ip_list_hash_size = 0,
  String     $ip_list_perms     = '0640',
  Integer[0] $ip_list_uid       = 0,
  Integer[0] $ip_list_gid       = 0
) {
  assert_private()

  if $set_rttl {
    $_rttl = '--rttl'
  }
  else {
    $_rttl = ''
  }

  if $enable {
    iptables_rule{'attk_check':
      order    => 28,
      header   => false,
      apply_to => 'all',
      # lint:ignore:only_variable_string
      content  => @("EOM")
        -A LOCAL-INPUT -m state --state NEW -j ATTK_CHECK
        -A ATTACKED -m limit --limit ${logs_per_minute}/min -j LOG --log-prefix "IPT: (Rule ATTACKED): "
        -A ATTACKED -m recent --set --name BANNED --rsource -j DROP
        -A ATTK_CHECK -m recent --set --name ATTK --rsource
        -A ATTK_CHECK -m recent --update --seconds ${seconds} --hitcount ${hitcount} ${_rttl} --name ATTK --rsource -j ATTACKED
        |EOM
    }
    # lint:endignore

    iptables_rule{'ban_check':
      order    => 7,
      apply_to => 'all',
      content  => "-m recent --update --seconds ${update_interval} --name BANNED --rsource -j DROP"
    }
  }

  class { 'iptables::rules::mod_recent':
    ip_list_tot       => $ip_list_tot,
    ip_pkt_list_tot   => $ip_pkt_list_tot,
    ip_list_hash_size => $ip_list_hash_size,
    ip_list_perms     => $ip_list_perms,
    ip_list_uid       => $ip_list_uid,
    ip_list_gid       => $ip_list_gid,
    notify_iptables   => true
  }
}
