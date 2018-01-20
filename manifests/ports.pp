# A define to allow for the standardization of the
#  iptables::ports syntax across modules 
#
# @param ports
#   A hash with structure as defined below that will open ports based on the
#   structure of the hash.
#   @example An example section of hieradata:
#     iptables::ports:
#       defaults:
#         apply_to: ipv4
#       80:
#       53:
#         proto: udp
#       443:
#         apply_to: ipv6
#
define iptables::ports (
  Hash $ports,
) {
  # extract defaults and remove that hash from iteration
  if $ports['defaults'].is_a(Hash) {
    $defaults  = $ports['defaults']
    $raw_ports = $ports - 'defaults'
  }
  else {
    $defaults  = {}
    $raw_ports = $ports
  }

  # https://docs.puppet.com/puppet/latest/reference/lang_resources_advanced.html#implementing-the-createresources-function
  $raw_ports.each |$port, $options| {
    $_port = Integer.new($port)
    $name_to_param = {
      'dports' => [$_port],
    }

    if $options.is_a(Hash) {
      $proto = $options['proto']
      $args  = ($options - 'proto') + $name_to_param
    }
    else {
      $proto = 'tcp'
      $args  = $name_to_param
    }

    case $proto {
      default: {
        iptables::listen::tcp_stateful {
          default:        * => $defaults;
          "port_${port}": * => $args;
        }
      }
      'udp': {
        iptables::listen::udp {
          default:        * => $defaults;
          "port_${port}": * => $args;
        }
      }
    }
  }
}