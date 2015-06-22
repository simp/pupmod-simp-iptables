# == Class: iptables::base_rules
#
# This class sets up the basic iptables rules pertinent to system security.
# The rules defined in here follow the following suggestion:
# * 1 -> ESTABLISHED,RELATED rules.
# * 2-5 -> Standard ACCEPT/DENY rules.
# * 6-10 -> Jumps to other rule sets.
# * 11-20 -> Pure accept rules.
# * 22-30 -> Logging and rejection rules.
# ---
#
# == Authors
#   * Trevor Vaughan <tvaughan@onyxpoint.com>
#
class iptables::base_rules (
  $allow_ping = true,
  $drop_broadcast = true,
  $drop_multicast = true,
){
  include 'iptables'

  iptables_rule { 'global':
    table    => 'filter',
    first    => true,
    absolute => true,
    header   => false,
    content  => '-A INPUT -j LOCAL-INPUT
                  -A FORWARD -j LOCAL-INPUT',
    apply_to =>  'all'
  }

  iptables_rule { 'allow_lo':
    table    => 'filter',
    order    => '2',
    content  => '-i lo -j ACCEPT',
    apply_to => 'all'
  }

  iptables_rule { 'established_related':
    table    => 'filter',
    order    => '1',
    content  => '-m state --state ESTABLISHED,RELATED -j ACCEPT',
    apply_to => 'all'
  }

  if $allow_ping {
    # Respond to pings per RFC 1122 - Section: 3.2.2.6
    iptables_rule { 'allow_v4_echo_request':
      table    => 'filter',
      order    => '11',
      content  => '-p icmp --icmp-type echo-request -j ACCEPT',
      apply_to => 'ipv4'
    }

    if $::ipv6_enabled {
      iptables_rule { 'allow_v6_echo_request':
        table    => 'filter',
        order    => '11',
        content  => '-p icmpv6 --icmpv6-type echo-request -j ACCEPT',
        apply_to => 'ipv6'
      }
    }

  }

  if $drop_broadcast {
    iptables_rule { 'drop_broadcast':
      table    => 'filter',
      order    => '27',
      content  => '-m pkttype --pkt-type broadcast -j DROP',
      apply_to => 'ipv4'
    }

    iptables_rule { 'drop_v6_broadcast':
      table    => 'filter',
      order    => '27',
      content  => '-m pkttype --pkt-type broadcast -j DROP',
      apply_to => 'ipv6'
    }
  }

  if $drop_multicast {
    iptables_rule { 'drop_v6_multicast':
      table    => 'filter',
      order    => '27',
      content  => '-m pkttype --pkt-type multicast -j DROP',
      apply_to => 'ipv6'
    }

    iptables_rule { 'drop_v4_multicast':
      table    => 'filter',
      order    => '27',
      content  => '-m addrtype --src-type MULTICAST -j DROP',
      apply_to => 'ipv4'
    }
  }

  # Log
  iptables_rule { 'log_all':
    table    => 'filter',
    order    => '29',
    content  => '-m state --state NEW -j LOG --log-prefix "IPT:"',
    apply_to => 'all'
  }

  # Drop All
  iptables_rule { 'drop_all':
    table    => 'filter',
    absolute => true,
    content  => '-j DROP',
    apply_to => 'all'
  }

}
