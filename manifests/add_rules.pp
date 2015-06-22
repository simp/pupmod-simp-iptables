#
# _Description_
#
# This function allows you to add rules to the iptables configuration
# file.  These rules should be uniquely named.  Rules are added to
# /etc/sysconfig/iptables.
#
# _Example_
#
#  Command
#     iptables::add_rules { 'example':
#         content => '-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp\
#         -s 1.2.3.4 --dport 1024:65535 -j ACCEPT'
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
#     -A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT
#     -A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#     -A LOCAL-INPUT -j LOG --log-prefix "IPT:"
#     -A LOCAL-INPUT -j DROP
#     COMMIT
#
define iptables::add_rules (
# _Variables_
#
# $content
#     The content of the rules that should be added.
    $content,
# $table
#     Should be the name of the table you are adding to.
    $table = 'filter',
# $first
#     Should be set to true if you want to prepend your custom rules.
    $first = false,
# $absolute
#     Should be set to true if you want the section to be absolutely first or
#     last, depending on the setting of $first.  This is relative and basically
#     places items in an alphabetical order.
    $absolute = false,
# $order
#     The order in which the rule should appear.  1 is the minimum and 9999999
#     is the max.
#
#     The following ordering ranges are suggested:
#       - 1    --> ESTABLISHED,RELATED rules.
#       - 2-5   --> Standard ACCEPT/DENY rules.
#       - 6-10  --> Jumps to other rule sets.
#       - 11-20 --> Pure accept rules.
#       - 22-30 --> Logging and rejection rules.
#   These are suggestions and are not enforced
    $order = '11',
# $comment
#     A comment to prepend to the rule
    $comment = '',
# $header
#     Whether or not to include the line header
#     '-A LOCAL-INPUT'.
    $header = true,
# $apply_to
#     Iptables target:
#       - ipv4 -> iptables
#       - ipv6 -> ip6tables
#       - all  -> Both
#       - auto -> Try to figure it out from the rule, will not pick
#                 'all'. (default)
    $apply_to = 'auto'
  ) {
  iptables_rule { $name:
    table    => $table,
    absolute => $absolute,
    first    => $first,
    order    => $order,
    header   => $header,
    content  => $content,
    apply_to => $apply_to
  }
}
