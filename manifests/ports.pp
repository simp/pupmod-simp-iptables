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
#       514:
#         proto:
#           - udp
#           - tcp
#
define iptables::ports (
  Hash $ports,
) {
  # extract defaults and remove that hash from iteration
  if $ports['defaults'] =~ Hash {
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

    if $options =~ Hash {
      if $options['proto'] {
        $proto = $options['proto']
      }
      elsif $defaults['proto'] {
        $proto = $defaults['proto']
      }
      else {
        $proto = 'tcp'
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

    if $proto =~ String {
      $_proto = [$proto]
    } else {
      $_proto = $proto
    }

    $_proto.each |$p| {
      case $p {
        'tcp': {
          iptables::listen::tcp_stateful { "port_${port}":
            * => $_defaults + $args,
          }
        }
        'udp': {
          iptables::listen::udp { "port_${port}":
            * => $_defaults + $args,
          }
        }
        default: {
          fail("port ${port} unknown proto ${p}")
        }
      }
    }
  }
}
