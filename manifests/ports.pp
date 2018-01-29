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

  $raw_ports.each |$port, $options| {
    $_port = Integer.new($port)
    $name_to_param = {
      'dports' => [$_port],
    }

    if $options.is_a(Hash) {
      if $options['proto'] {
        $proto = $options['proto']
      }
      else {
        $proto = $defaults['proto']
      }
      $_defaults = $defaults - 'proto'
      $args      = ($options - 'proto') + $name_to_param
    }
    else {
      if $defaults['proto'] {
        $proto = $defaults['proto']
      }
      else {
        $proto = 'tcp'
      }
      $_defaults = $defaults - 'proto'
      $args  = $name_to_param
    }

    case $proto {
      default: {
        iptables::listen::tcp_stateful {
          default:        * => $_defaults;
          "port_${port}": * => $args;
        }
      }
      'udp': {
        iptables::listen::udp {
          default:        * => $_defaults;
          "port_${port}": * => $args;
        }
      }
    }
  }
}