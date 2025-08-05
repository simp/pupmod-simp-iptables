# Install the IPTables and IP6Tables components
#
# @param ipv4_package
#   The package used to manage ipv4 rules
#
#   * Default from module data
#
# @param ipv6_package
#   The package used to manage ipv6 rules
#
#   * Default from module data
#
class iptables::install (
  String[1] $ipv4_package,
  String[1] $ipv6_package
) {
  assert_private()

  simplib::assert_metadata($module_name)

  stdlib::ensure_packages($ipv4_package, { 'ensure' => $iptables::ensure })

  if $iptables::ipv6 and $facts['ipv6_enabled'] {
    stdlib::ensure_packages($ipv6_package, { 'ensure' => $iptables::ensure })
  }
}
