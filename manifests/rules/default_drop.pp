# **NOTE: THIS IS A [PRIVATE](https://github.com/puppetlabs/puppetlabs-stdlib#assert_private) CLASS**
#
# Manage the default policy settings of the built in chains.
#
# Given that there is a well-defined, and limited, set of built-in chains this
# class fully enumerates the combinations to maximize readability.
#
# * Setting any parameter to `true` will activate the DROP condition.
# * Setting any parameter to `false` will activate the ACCEPT condition.
# * Leaving a parameter unset will not change the state of the system.
#
# NOTE: If you need different settings for IPv6 and IPv4 then you will need to
# create your own resources
#
# @param filter_input
# @param filter_forward
# @param filter_output
#
class iptables::rules::default_drop (
  Optional[Boolean] $filter_input   = undef,
  Optional[Boolean] $filter_forward = undef,
  Optional[Boolean] $filter_output  = undef
) {
  assert_private()

  $_xlat = {
    true  => 'DROP',
    false => 'ACCEPT',
  }

  if $filter_input =~ NotUndef {
    iptables_default_policy { 'filter:INPUT':
      policy => $_xlat[$filter_input],
    }
  }

  if $filter_forward =~ NotUndef {
    iptables_default_policy { 'filter:FORWARD':
      policy => $_xlat[$filter_forward],
    }
  }

  if $filter_output =~ NotUndef {
    iptables_default_policy { 'filter:OUTPUT':
      policy => $_xlat[$filter_output],
    }
  }
}
