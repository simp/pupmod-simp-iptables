# Add management of iptables with default rule optimization and a failsafe
# fallback mode
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
#   * If set to ``false`` will **disable** IPTables completely
#   * If set to ``ignore`` will stop managing IPTables
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
#   * IPsets will be eventually be incorporated
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
# @param ports [Hash]
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
# @author Trevor Vaughan <tvaughan@onyxpoint.com>
# @author Chris Tessmer  <chris.tessmer@onyxpoint.com>
#
class iptables (
  Variant[Enum['ignore'],Boolean] $enable                     = simplib::lookup('simp_options::firewall', { 'default_value' => true }),
  String                          $ensure                     = 'latest',
  Boolean                         $ipv6                       = true,
  Boolean                         $class_debug                = false,
  Boolean                         $optimize_rules             = true,
  Array[String]                   $ignore                     = [],
  Boolean                         $default_rules              = true,
  Boolean                         $scanblock                  = false,
  Boolean                         $prevent_localhost_spoofing = true,
  Optional[Hash]                  $ports                      = undef
) {

  if $enable != 'ignore' {
    contain '::iptables::install'
    contain '::iptables::service'

    if $default_rules { contain '::iptables::rules::base' }
    if $scanblock { contain '::iptables::rules::scanblock' }
    if $prevent_localhost_spoofing { contain '::iptables::rules::prevent_localhost_spoofing' }

    Class['iptables::install'] -> Class['iptables::service']

    # These are required to run if you are managing iptables with the custom
    # types at all.
    iptables_optimize { '/etc/sysconfig/iptables':
      optimize => $optimize_rules,
      ignore   => $ignore,
      disable  => !$enable
    }

    if $ipv6 and $facts['ipv6_enabled'] {
      ip6tables_optimize { '/etc/sysconfig/ip6tables':
        optimize => $optimize_rules,
        ignore   => $ignore,
        disable  => !$enable
      }
    }
  }

  if $ports {
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
      $name_to_param = {
        'dports' => [$port],
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

}
