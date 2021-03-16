# @summary Manage iptables with default rule optimization and a failsafe fallback mode
#
# ----------
#
# > It is **highly recommended** that you place this module in ``firewalld``
# > mode if the underlying system supports it.
# >
# > You can do this by setting ``iptables::use_firewalld: true`` in Hiera
#
# ----------
#
# This class will detect conflicts with the SIMP option
# ``simp_options::firewall`` and, if necessary, cease management of IPTables in
# the case of a conflict.
#
# In particular, this means that if ``simp_options::firewall`` is ``false``,
# but you have included this class, it will refuse to manage IPTables and will
# instead raise a warning.
#
# If the ``simp_options::firewall`` variable is not present, the module will
# manage IPTables as expected.
#
# @param enable
#   Enable IPTables
#
#   * If set to ``true`` will **enable** management of IPTables
#   * If set to ``false`` will **disable** IPTables completely
#   * If set to ``ignore`` will stop managing IPTables
#
# @param use_firewalld
#   Explicitly enable management via ``simp_firewalld``
#
#   * Systems that do not have ``firewalld`` installed will fall back to ``iptables``
#
# @param ensure
#   The state that the ``package`` resources should target
#
#   * May take any value acceptable to the native ``package`` resource
#     ``ensure`` parameter
#
# @param ipv6
#   Also manage IP6Tables
#
# @param class_debug
#   Print messages regarding rule comparisons
#
# @param optimize_rules
#   Run the inbuilt iptables rule optimizer to collapse the rules down to as
#   small as is reasonably possible without reordering
#
#   * IPSets have been incorporated via the `firewalld` module
#
# @param precise_match
#   Instead of matching rule counts, perform a more precise match against the
#   running and to-be-applied rules. You may find that minor changes, such as a
#   simple netmask change will not be enforced without enabling this option.
#
#   * NOTE: You **MUST** use the exact same syntax that will be returned by
#     `iptables-save` and `ip6tables-save` if you use this option!
#   * For example, you cannot write `echo-request` for an ICMP echo match, you
#     must instead use `8`.
#
# @param ignore
#   Regular expressions that you would like to match in order to preserve
#   running rules
#
#   * This modifies the behavior of the ``iptables_optimize`` Type.
#   * Do **not** include the beginning and ending ``/`` but **do** include an
#     end or beginning of word marker (``^`` and/or ``$``) if appropriate
#
# @param default_rules
#   Enable the usual set of default deny rules that you would expect to see on
#   most systems
#
#   * Uses the following expectations of rule ordering (not enforced):
#       * 1     -> ``ESTABLISHED`` and ``RELATED`` rules
#       * 2-5   -> Standard ``ACCEPT`` and ``DENY`` rules
#       * 6-10  -> ``JUMP`` to other rule sets
#       * 11-20 -> Pure ``ACCEPT`` rules
#       * 22-30 -> ``LOG`` and ``REJECT`` rules
#
# @param scanblock
#   Enable a technique for setting up port-based triggers that will block
#   anyone connecting to the system for an hour after connection to a forbidden
#   port
#
# @param prevent_localhost_spoofing
#   Add rules to ``PREROUTING`` that will prevent spoofed packets from
#   ``localhost`` addresses from reaching your system
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
# @author https://github.com/simp/pupmod-simp-iptables/graphs/contributors
#
class iptables (
  Variant[Enum['ignore','firewalld'],Boolean] $enable         = simplib::lookup('simp_options::firewall', { 'default_value' => true }),
  Boolean                         $use_firewalld              = iptables::use_firewalld($enable),
  String                          $ensure                     = simplib::lookup('simp_options::package_ensure', { 'default_value' => 'installed' }),
  Boolean                         $ipv6                       = true,
  Boolean                         $class_debug                = false,
  Boolean                         $optimize_rules             = true,
  Boolean                         $precise_match              = false,
  Array[String[1]]                $ignore                     = [],
  Boolean                         $default_rules              = true,
  Boolean                         $scanblock                  = false,
  Boolean                         $prevent_localhost_spoofing = true,
  Optional[Hash]                  $ports                      = undef
) {

  simplib::assert_metadata($module_name)

  $firewalld_mode = ( 'firewalld' in pick($facts['simplib__firewalls'], 'none') ) and $use_firewalld
  if $enable != 'ignore' {
    # This is required in case you want to put firewalld in iptables mode
    contain 'iptables::install'

    if $firewalld_mode {
      simplib::assert_optional_dependency($module_name, 'simp/simp_firewalld')

      include 'simp_firewalld'

      if $ports {
        iptables::ports {'firewalld':
          ports => $ports
        }
      }
    }
    else {
      contain 'iptables::service'

      if $default_rules { contain 'iptables::rules::base' }
      if $scanblock { contain 'iptables::rules::scanblock' }
      if $prevent_localhost_spoofing { contain 'iptables::rules::prevent_localhost_spoofing' }

      contain 'iptables::rules::default_drop'

      Class['iptables::install'] -> Class['iptables::service']

      file { '/etc/sysconfig/iptables':
        owner   => 'root',
        group   => 'root',
        mode    => '0640',
        require => Class['iptables::install']
      }

      # These are required to run if you are managing iptables with the custom
      # types at all.
      iptables_optimize { '/etc/sysconfig/iptables':
        optimize      => $optimize_rules,
        ignore        => $ignore,
        disable       => !$enable,
        precise_match => $precise_match,
        require       => Class['iptables::install']
      }

      if $ipv6 and $facts['ipv6_enabled'] {
        file { '/etc/sysconfig/ip6tables':
          owner   => 'root',
          group   => 'root',
          mode    => '0640',
          require => Class['iptables::install']
        }

        ip6tables_optimize { '/etc/sysconfig/ip6tables':
          optimize      => $optimize_rules,
          ignore        => $ignore,
          disable       => !$enable,
          precise_match => $precise_match,
          require       => Class['iptables::install']
        }
      }

      if $ports {
        iptables::ports {'iptables':
          ports   => $ports,
          require => Class['iptables::install']
        }
      }
    }
  }
}
