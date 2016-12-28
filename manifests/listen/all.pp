# Allow all protocols to all ports from a select set of networks
#
# @example Open Access to Hosts ```1.2.3.4`` and ``5.6.7.8``
#   iptables::listen::all { 'example':
#     trusted_nets => [ '1.2.3.4', '5.6.7.8' ],
#   }
#
#   ### Result
#
#   *filter
#   :INPUT DROP [0:0]
#   :FORWARD DROP [0:0]
#   :OUTPUT ACCEPT [0:0]
#   :LOCAL-INPUT - [0:0]
#   -A INPUT -j LOCAL-INPUT
#   -A FORWARD -j LOCAL-INPUT
#   -A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
#   -A LOCAL-INPUT -i lo -j ACCEPT
#   -A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
#   -A LOCAL-INPUT -s 1.2.3.4 -j ACCEPT
#   -A LOCAL-INPUT -s 5.6.7.8 -j ACCEPT
#   -A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#   -A LOCAL-INPUT -j LOG --log-prefix "IPT:"
#   -A LOCAL-INPUT -j DROP
#   COMMIT
#
# @param first
#   Prepend this rule to the rule set
#
# @param absolute
#   Make sure that this rule is absolutely first, or last, depending on the
#   setting of ``first``
#
#   * If ``first`` is true, this rule will be at the top of the list
#   * If ``first`` is false, this rule will be at the bottom of the list
#   * For all ``absolute`` rules, alphabetical sorting still takes place
#
# @param order
#   The order in which the rule should appear
#
#   * 1 is the minimum and 9999999 is the maximum
#
#   * The following ordering ranges are suggested (but not enforced):
#
#       * 1     -> ESTABLISHED,RELATED rules
#       * 2-5   -> Standard ACCEPT/DENY rules
#       * 6-10  -> Jumps to other rule sets
#       * 11-20 -> Pure accept rules
#       * 22-30 -> Logging and rejection rules
#
# @param apply_to
#   The IPTables network type to which to apply this rule
#
#   * ipv4 -> iptables
#   * ipv6 -> ip6tables
#   * all  -> Both
#   * auto -> Try to figure it out from the rule, will **not** pick ``all``
#
# @param trusted_nets
#   Client networks that should be allowed
#
#   Set to ``any`` to allow all networks
#
define iptables::listen::all (
  Boolean                          $first        = false,
  Boolean                          $absolute     = false,
  Integer[0]                       $order        = 11,
  Enum['ipv4','ipv6','all','auto'] $apply_to     = 'auto',
  Simplib::Netlist                 $trusted_nets = simplib::lookup('simp_options::trusted_nets', { 'default_value' => ['127.0.0.1'] })
){
  iptables_rule { "all_${name}":
    first    => $first,
    absolute => $absolute,
    order    => $order,
    apply_to => $apply_to,
    content  => template("${module_name}/allow_all_services.erb")
  }
}
