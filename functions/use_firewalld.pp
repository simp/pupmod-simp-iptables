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
function iptables::use_firewalld(
  Variant[String[1], Boolean] $enable = true
) {

  $_firewalld_os_list = {
    'RedHat'      => '8',
    'CentOS'      => '8',
    'OracleLinux' => '8'
  }

  if $enable {
    $_simplib_firewalls = fact('simplib__firewalls')
    $_os_name = fact('os.name')
    $_os_maj_rel = fact('os.release.major')

    if $_simplib_firewalls and ('firewalld' in $_simplib_firewalls) {
      if ($enable == 'firewalld') or
        ($_firewalld_os_list[$_os_name] and ($_firewalld_os_list[$_os_name] <= $_os_maj_rel))
      {
        $_retval = true
      }
    }
  }

  unless defined('$_retval') {
    $_retval = false
  }

  $_retval
}
