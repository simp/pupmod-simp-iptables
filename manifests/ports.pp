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
#         proto: [udp,tcp]
#
define iptables::ports (
  Hash $ports,
) {

  $ports_hash = iptables::parse_ports($ports)

  $ports_hash.each |$res_name,$data| {
    case $res_name {
      default:        { iptables::listen::tcp_stateful { $res_name: * => $data; } }
      Pattern[/udp/]: { iptables::listen::udp {          $res_name: * => $data; } }
    }
  }
}
