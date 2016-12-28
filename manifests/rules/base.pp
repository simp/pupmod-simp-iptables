# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Set up the basic iptables rules pertinent to system security
#
# The rules defined in here follow the following suggestion:
# * 1     -> ESTABLISHED,RELATED rules.
# * 2-5   -> Standard ACCEPT/DENY rules.
# * 6-10  -> Jumps to other rule sets.
# * 11-20 -> Pure accept rules.
# * 22-30 -> Logging and rejection rules.
#
# @param allow_ping
#   Allow ICMP type 8 (ping) packets into the host
#
#   * This is enabled by default for RFC 1122 compliance
#
# @see https://tools.ietf.org/html/rfc1122#page-42 RFC 1122 Section 3.2.2.6
#
# @param drop_broadcast
#   Drop all broadcast traffic to this host
#
# @param drop_multicast
#   Drop all multicast traffic to this host
#
class iptables::rules::base (
  Boolean $allow_ping     = true,
  Boolean $drop_broadcast = true,
  Boolean $drop_multicast = true
){
  assert_private()

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

    if ( defined('$::ipv6_enabled') and getvar('::ipv6_enabled') ) {
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
