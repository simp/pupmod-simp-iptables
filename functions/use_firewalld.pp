# Returns ``true`` if the client can/should use firewalld
#
# @param enable
#   The type of enablement to use
#
#   * true      => Do the right thing based on the underlying OS
#   * false     => Return `false`
#   * firewalld => Force `firewalld` if available
#
# @return [Boolean]
#
function iptables::use_firewalld (
  Variant[String[1], Boolean] $enable = true,
) >> Boolean {
  if $enable {
    $_simplib_firewalls = fact('simplib__firewalls')

    if $_simplib_firewalls and ('firewalld' in $_simplib_firewalls) {
      if ($enable == 'firewalld') {
        $_retval = true
      }
    }
  }

  unless defined('$_retval') {
    $_retval = false
  }

  $_retval
}
