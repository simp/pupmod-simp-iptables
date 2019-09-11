# Add rules to the IPTables configuration file
#
# @example Add a TCP Allow Rule
#   iptables::rule { 'example':
#     content => '-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT'
#   }
#
#  ### Result:
#
#  *filter
#  :INPUT DROP [0:0]
#  :FORWARD DROP [0:0]
#  :OUTPUT ACCEPT [0:0]
#  :LOCAL-INPUT - [0:0]
#  -A INPUT -j LOCAL-INPUT
#  -A FORWARD -j LOCAL-INPUT
#  -A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
#  -A LOCAL-INPUT -i lo -j ACCEPT
#  -A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
#  -A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT
#  -A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#  -A LOCAL-INPUT -j LOG --log-prefix "IPT:"
#  -A LOCAL-INPUT -j DROP
#  COMMIT
#
# @param content
#   The **exact** content of the rule that should be added
#
#   * If this module is run in ``firewalld`` mode, this needs to contain a JSON
#     string that can include, but is not limited to:
#
#     * dports
#     * trusted_nets
#     * protocol
#     * icmp_blocks
#
#   * In ``firewalld`` mode, the following parameters will be ignored:
#
#     * table
#     * first
#     * absolute
#     * order
#     * header
#
# @param table
#   The name of the table you are adding to
#
#   * Usual names include (but are not limited to):
#
#       * filter
#       * mangle
#       * nat
#       * raw
#       * security
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
# @param header
#   Automatically add the line header ``-A LOCAL-INPUT``
#
# @param apply_to
#   The IPTables network type to which to apply this rule
#
#   * ipv4 -> iptables
#   * ipv6 -> ip6tables
#   * all  -> Both
#   * auto -> Try to figure it out from the rule, will **not** pick ``all``
#
define iptables::rule (
  String            $content,
  String            $table    = 'filter',
  Boolean           $first    = false,
  Boolean           $absolute = false,
  Integer[0]        $order    = 11,
  Boolean           $header   = true,
  Iptables::ApplyTo $apply_to = 'auto'
) {
  include iptables

  if $iptables::use_firewalld {
    simplib::assert_optional_dependency($module_name, 'puppet/firewalld')

    $_metadata = parsejson($content)

    if $_metadata['protocol'] == 'icmp' {
      $_dports = undef
      $_icmp_block = Array($_metadata['icmp_types'])
    }
    else {
      if $_metadata['dports'] {
        $_dports_a = Array($_metadata['dports'], true)
        $_dports = $_dports_a.map |$dport| {
          # Convert all IPTables range formats over to firewalld formats
          $_converted_port = regsubst("${dport}",':','-') # lint:ignore:only_variable_string

          if $_metadata['protocol'] != 'all' {
            {
              'port'     => $_converted_port,
              'protocol' => $_metadata['protocol']
            }
          }
          else {
            {
              'port' => $_converted_port
            }
          }
        }

        firewalld::custom_service { "simp_${name}":
          short       => "simp_${name}",
          description => "SIMP ${name}",
          port        => $_dports,
          require     => Service['firewalld']
        }
      }
      else {
        $_dports = undef
      }
    }

    $_trusted_nets = Array($_metadata['trusted_nets'], true)

    # These cases indicate that only a service should be added to the zone and
    # not an ipset since it will allow from anywhere and the rest of the
    # matches are irrelevant at that point.
    if ['0.0.0.0/0', '::/0', '[::]/0', 'ALL'].any |$x| { $x in $_trusted_nets } {
      $_allow_from_all = true
    }
    else {
      $_allow_from_all = false
    }

    # It only makes sense to create this if we have been passed some ports to
    # bind it to.
    if $_dports and $_allow_from_all {
      firewalld_service { "simp_${name}":
        zone    => 'simp',
        require => Service['firewalld']
      }
    }
    else {
      if $_allow_from_all {
        if ($apply_to == 'ipv4') {
          $_trusted_nets_hash = simplib::ip::family_hash(['0.0.0.0/0'])
        }
        elsif ($apply_to == 'ipv6') {
          $_trusted_nets_hash = simplib::ip::family_hash(['::/0'])
        }
        else {
          $_trusted_nets_hash = simplib::ip::family_hash(['0.0.0.0/0', '::/0'])
        }
      }
      else {
        $_trusted_nets_hash = simplib::ip::family_hash($_trusted_nets)
      }

      # We need to perform the correct action based on each IP Address family
      # in the $_trusted_nets Array
      $_trusted_nets_hash.keys.each |$_ip_family| {

        # Only activate on the correct type of IP address
        if ($apply_to == 'all') or ($apply_to == 'auto') or ($apply_to == $_ip_family) {

          # Determine what can go into an IPSet and what can't
          $_split_entries = $_trusted_nets_hash[$_ip_family].reduce({'base' => [], 'ipset' => []}) |$memo, $x| {
            $_data = $x[-1]
            if (($_ip_family == 'ipv4') and ($_data['netmask']['cidr'] == 32)) or
              (($_ip_family == 'ipv6') and ($_data['netmask']['cidr'] == 128)) {
              {
                'base' => $memo['base'],
                'ipset'   => $memo['ipset'] + $_data['address']
              }
            }
            else {
              {
                'base' => $memo['base'] + "${_data['address']}/${_data['netmask']['cidr']}",
                'ipset'   => $memo['ipset']
              }
            }
          }

          if empty($_split_entries['ipset']) {
            $_sources = $_split_entries['base']
          }
          else {
            # Create a unique ipset based on the bare addresses
            #
            # This is done so that we do not end up with a million ipsets for every call
            #
            # The length is limited due to apparent limitations in the ipset name
            $_ipset_family = $_ip_family ? { 'ipv6' => 'inet6', default => 'inet' }

            $_ipset_name = join(['simp', $_ipset_family, seeded_rand_string(20, join([$name] + sort(unique($_trusted_nets)),''))], '_')[0,31]
            ensure_resource('firewalld_ipset', $_ipset_name,
              {
                'entries' => $_split_entries['ipset'],
                'options' => {
                  'family' =>  $_ipset_family
                },
                require   => Service['firewalld']
              }
            )

            $_sources = ($_split_entries['base'] + [{ 'ipset' => $_ipset_name }])
          }

          $_sources.each |$_source| {
            # We need this because the underlying types can't handle Arrays

            $_unique_name = regsubst(join([
              $order,
              'simp',
              $name,
              $_ip_family,
              simplib::to_string($_source).regsubst('[^0-9a-z ]', '_', 'GI')
            ], '_'), '_+', '_', 'G')

            if $_metadata['protocol'] == 'icmp' {
              firewalld_rich_rule { $_unique_name:
                ensure     => 'present',
                family     => $_ip_family,
                source     => $_source,
                icmp_block => $_icmp_block,
                action     => 'accept',
                zone       => 'simp',
                require    => Service['firewalld']
              }
            }
            else {
              # If we don't have any ports, then we don't have a service to
              # bind to. This probably means that we were called in a way to
              # allow all traffic to a specific IP address.
              if $_dports {
                $_rich_rule_svc = "simp_${name}"
              }
              else {
                $_rich_rule_svc = undef
              }

              firewalld_rich_rule { $_unique_name:
                ensure  => 'present',
                family  => $_ip_family,
                source  => $_source,
                service => $_rich_rule_svc,
                action  => 'accept',
                zone    => 'simp',
                require => Service['firewalld']
              }
            }
          }
        }
      }
    }
  }
  else {
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
}
