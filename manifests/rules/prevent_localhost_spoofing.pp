# Add rules that prevent external parties from being able to send spoofed
# packets to your system from ::1
#
# The sysctl setting for rp_filter handles this for IPv4
#
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::rules::prevent_localhost_spoofing {
  assert_private()

  if $::iptables::ipv6 and $facts['ipv6_enabled'] {
    iptables_rule{ 'prevent_ipv6_localhost_spoofing':
      table    => 'raw',
      comment  => 'Prevent Spoofing of Localhost Addresses',
      first    => true,
      header   => false,
      apply_to => 'ipv6',
      content  => '-A PREROUTING ! -i lo -s ::1 -j DROP'
    }
  }
}
