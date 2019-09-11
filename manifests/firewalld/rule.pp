# Add firewall rules via firewalld
#
# This is primarily meant for use with the iptables::listen::* defined types.
# If you wish to do direct manipulation of firewalld rules it is recommended
# that you use the Hiera-native capabilities of the firewalld module directly.
#
# @param trusted_nets
#   The networks/hosts to which the rule applies
#
# @param protocol
#   The network protocol to which the rule applies
#
# @param dports
#   The ports to which the rule applies
#
# @param icmp_blocks
#   The ICMP Blocks to which the rule applies
#
# @param order
#   The order in which the rule should appear
#
#   Due to the way firewalld works, this may not do what you expect unless the
#   version of firewalld explicitly supports it.
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
#   The address family to which to apply this rule
#
#   * ipv4 -> iptables
#   * ipv6 -> ip6tables
#   * all  -> Both
#   * auto -> Try to figure it out from the rule, defaults to ``all``
#
define iptables::firewalld::rule (
  Simplib::Netlist                        $trusted_nets,
  Enum['icmp','tcp','udp','all']          $protocol,
  Optional[Iptables::DestPort]            $dports        = undef,
  Optional[Variant[Array[String],String]] $icmp_blocks   = undef,
  Integer[0]                              $order         = 11,
  Iptables::ApplyTo                       $apply_to      = 'auto'
) {
  simplib::assert_optional_dependency($module_name, 'puppet/firewalld')

  if $protocol == 'icmp' {
    $_dports = undef
    $_icmp_block = Array($icmp_blocks)
  }
  else {
    if $dports {
      $_dports_a = Array($dports, true)
      $_dports = $_dports_a.map |$dport| {
        # Convert all IPTables range formats over to firewalld formats
        $_converted_port = regsubst("${dport}",':','-') # lint:ignore:only_variable_string

        if $protocol != 'all' {
          {
            'port'     => $_converted_port,
            'protocol' => $protocol
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

  $_trusted_nets = Array($trusted_nets, true)

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

          if $protocol == 'icmp' {
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
