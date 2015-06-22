# == Define iptables::add_all_listen
#
# This define provides a simple way to allow all protocols to all ports on the target
# system from a select set of networks.
#
# _Templates_
#
# * allow_all_services.erb
#
# _Example_
#
#  Command
#     iptables::add_all_listen { 'example':
#       client_nets => [ '1.2.3.4', '5.6.7.8' ],
#     }
#
#  Output (to /etc/sysconfig/iptables)
#     *filter
#     :INPUT DROP [0:0]
#     :FORWARD DROP [0:0]
#     :OUTPUT ACCEPT [0:0]
#     :LOCAL-INPUT - [0:0]
#     -A INPUT -j LOCAL-INPUT
#     -A FORWARD -j LOCAL-INPUT
#     -A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
#     -A LOCAL-INPUT -i lo -j ACCEPT
#     -A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
#     -A LOCAL-INPUT -s 1.2.3.4 -j ACCEPT
#     -A LOCAL-INPUT -s 5.6.7.8 -j ACCEPT
#     -A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#     -A LOCAL-INPUT -j LOG --log-prefix "IPT:"
#     -A LOCAL-INPUT -j DROP
#     COMMIT
#
define iptables::add_all_listen (
# _Variables_
#
# $first
#     Should be set to true if you want to prepend your custom rules.
    $first = false,
# $absolute
#     Should be set to true if you want the section to be absolutely first or
#     last, depending on the setting of $first.  This is relative and basically
#     places items in alphabetical order.
    $absolute = false,
# $order
#     The order in which the rule should appear.  1 is the minimum, 11 is the
#     mean, and 9999999 is the max.
#     The following ordering ranges are suggested:
#       - 1    --> ESTABLISHED,RELATED rules.
#       - 2-5   --> Standard ACCEPT/DENY rules.
#       - 6-10  --> Jumps to other rule sets.
#       - 11-20 --> Pure accept rules.
#       - 22-30 --> Logging and rejection rules.
#     These are suggestions and are not enforced.
    $order = '11',
# $apply_to
#     Iptables target:
#       - ipv4 -> iptables
#       - ipv6 -> ip6tables
#       - all  -> Both
#       - auto -> Try to figure it out from the rule, will not pick
#                 'all'. (default)
    $apply_to = 'auto',
# $client_nets
#     Client networks that should be allowed by this rule.
#     Set the string to 'any' to allow all networks
    $client_nets = '127.0.0.1')
{
  iptables_rule { "all_$name":
    first    => $first,
    absolute => $absolute,
    order    => $order,
    apply_to => $apply_to,
    content  => template('iptables/allow_all_services.erb')
  }

  validate_net_list($client_nets,'^(any|ALL)$')
}
