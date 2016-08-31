[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html) [![Build Status](https://travis-ci.org/simp/pupmod-simp-iptables.svg)](https://travis-ci.org/simp/pupmod-simp-iptables) [![SIMP compatibility](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)](https://img.shields.io/badge/SIMP%20compatibility-4.2.*%2F5.1.*-orange.svg)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with iptables](#setup)
    * [What iptables affects](#what-iptables-affects)
    * [Beginning with iptables](#beginning-with-iptables)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
    * [Native Types](#native-types)
      * [iptables_rule](#iptables_rule)
      * [iptables_optimize](#iptables_optimize)
      * [ip6tables_optimize](#ip6tables_optimize)
      * [xt_recent](#xt_recent)
    * [Classes](#classes)
      * [iptables](#iptables)
    * [Defined Types](#defined-types)
      * [add_all_listen](#add_all_listen)
      * [add_icmp_listen](#add_icmp_listen)
      * [add_rules](#add_rules)
      * [add_tcp_stateful_listen](#add_tcp_stateful_listen)
      * [add_udp_stateful_listen](#add_udp_stateful_listen)

6. [Limitations - OS compatibility, etc.](#limitations)
7. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

This module provides native types for managing the system IPTables and IP6Tables as well as convenience defines and general system configuration capabilities.

## This is a SIMP module
This module is a component of the [System Integrity Management Platform](https://github.com/NationalSecurityAgency/SIMP), a compliance-management framework built on Puppet.

Most SIMP modules actively take advantage of this module when used within the SIMP ecosystem.

## Module Description

The `iptables` module manages all IPTables and IP6Tables rules in an atomic fashion. All rules are applied only once per puppet agent run during the application of the last executed `iptables` resource.

Applying the rules in this manner ensures that avoid situations where you have a partially applied IPTables rule set during a failure in your run of puppet (someone hits ^C, your system runs out of memory, etc...).

The module also takes additional safety measures to attempt to keep your firewall rules in a consistent state over time to include:

* Rolling back to the last configuration if the application of the new configuration fails
* Rolling back to an 'ssh-only' mode if application of all configurations fail

The goal is to remain in a state where you can be sure that your system is tightly restricted but also able to be recovered.

Finally, the module works to ensure that services such as OpenStack, Docker, VirtualBox, etc... can apply their rules without being affected by this module. The module provides mechanisms to preserve these rules as managed by external systems based on regular expression matches.

## Setup

### What iptables affects

The module manages the `iptables` package, service, and rules.

On systems containing the `firewalld` service, it is ensured to be stopped.

### Beginning with iptables

#### I want a basic secure iptables setup

A basic setup with iptables will allow the following:

* ICMP
* Loopback
* SSH
* Estabilished and Related traffic (Return Traffic)

```puppet
# Set up iptables with the default settings

include '::iptables'
```
Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

## Usage

#### I want to open a specific port or allow access

The IPtables module has a set of defined types for adding in new firewall rules. This code can be utilized in a role or profile.

```puppet
#open TCP port 443 (HTTPS) and a custom 8443 from any IP Address

iptables::add_tcp_stateful_listen { 'webserver':
  client_nets => ['any'],
  dports => ['443','8443']
}

#open UDP port 53 (DNS) from two specific IP addresses

iptables::add_udp_stateful_listen {'DNS':
  client_nets => ['192.168.56.55','192.168.56.147'],
  dports      => ['53']
}

#Allow a specific machine full access to this node

iptables::add_all_listen { 'Central Management':
  client_nets => ['10.10.35.100'],
}

#Allow a range of ports to be accessible from a specific IP
iptables::add_tcp_stateful_listen { 'myapp':
  client_nets => ['10.10.45.100'],
  dports => ['1024:60000']
}

```

#### This module doesn't cover my specific iptables rule

In the case you need a rule not covered properly by the module, you can use the iptables::add_rules type to place the exact rule into /etc/sysconfig/iptables.

```puppet
# Inserts a custom rule into IPtables

iptables::add_rules { 'example':
  content => '-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp\
  -s 1.2.3.4 --dport 1024:65535 -j ACCEPT'
}
```

## Reference

### Native Types

#### `iptables_rule`

A managed iptables rule. This may be used to provide ultimate flexibility in managing the system rules.

##### Parameters

* name: A unique name for the rule, does not provide any other function. Required
* comment: A comment to apply to the rule. Default: No Comment
* header: Whether or not to auto-include the table LOCAL-INPUT in the rule. Default: true
* apply_to: What version(s) of iptables to which to apply this rule. Default: 'auto'
  If set to 'auto' (the default) then we'll try to guess what you want and default to ['ipv4','ipv6'].
  If 'auto' is set then each line will be evaluated as an independent rule.
    * Any rules that have IPv4 addresses will be applied to iptables.
    * Any rules that have IPv6 addresses will be applied to ip6tables.
    * All other rules will be applied to *both* utilities.
    * If in doubt, split your rules and specify your tables!

* table: The name of the table to which you are adding the rule. Default: 'filter'
* first: If `true`, prepend the rule to the rule set. Default: `false`
* absolute: If `true`, ensure that the rule is at the absolute beginning or end of the rule set. If multiple rules are marked as absolute then they are sorted by resource name. Default: `false`
* order: The order in which the rule should appear. 1 is the minimum and 999 is the maximum. Default: '11'
* resolve: If `true`, Puppet will resolve any hostnames in the rules prior to application to prevent iptables from starting should a name change in the future. Default: `true`
* content: The full content of the rule that should be added to the rule set. You may place *anything* here. Required

#### iptables_optimize
#### ip6tables_optimize

This type collects all of the `iptables_rule` resources and compiles the final iptables rule set. By default, it will collapse rules into a single rule when possible to make the iptables rule set more efficient. Eventually, it will support `ipset`.

The ip6tables_optimize type has the exact same parameters but affects ip6tables instead of iptables.

##### Parameters

* name: An arbitrary name for the resource. This resource is not meant to be called more than once...
* disable: If `true`, disable the management of iptables altogether. Default: `false`
* ignore: Ignore all *running* iptables rules matching one or more provide Ruby regular expressions. The regular expressions are compared against both the JUMP and CHAIN options of the running rules. Anything matching these rules are excluded from the synchronization comparison against the new rules.

  **Caveats**

  Do NOT include the beginning and trailing slashes in your regular expressions.

  If a rule has been added or removed, this setting ignored and iptables *will*
be restarted! If you have services which are affected by this, make sure that
they subscribe to Service['iptables'] and/or Service['ip6tables'] as
appropriate.

  **Examples**
  ```
  # Preserve all rules whose jump or chain begins with the word 'foo'
  ignore => '^foo'

  # Preserve all rules whose jump or chain begins with the word 'foo' or
  # ends with the word 'bar'
  ignore => ['^foo','bar$']
  ```

* optimize: If `true`, enable the optimization of the IPTables rules. Default: `true`

#### xt_recent

##### Parameters

* name: The path to the xt_recent variables to be manipulated
* ip_list_tot: The number of addresses remembered per table. This effectively becomes the maximum size of your block list. The more addresses you are recording, the higher the load on your system. Default: '100'
* ip_pkt_list_tot: The number of packets per address remembered. Default: '20'
* ip_list_hash_size: The hash table size. 0 means to calculate it based on ip_list_tot. Default: '0'
* ip_list_perms: Permissions for /proc/net/xt_recent/* files. Default: '0640'
* ip_list_uid: Numerical UID for ownership of /proc/net/xt_recent/* files. Defafult: '0'
* ip_list_gid: Numerical GID for ownership of /proc/net/xt_recent/* files. Defafult: '0'

### Classes

#### `iptables`

This sets the system up in a way that will maximally utilize the iptables native types.

##### Parameters

* `authoritative`: If true, only iptables rules set by Puppet may be present on the system. Otherwise, only manage the *chains* that Puppet is managing.  Default: true

  **WARNING:**  Be *extremely* careful with this option. If you don't match all of your rules that you want left around, but you also don't have something to clean up the various tables, you will get continuous warnings that IPTables rules are being optimized.

* `class_debug`: If true, the system will print messages regarding rule comparisons.  Default: false
* `optimize_rules`: If true, the inbuilt iptables rule optimizer will be run to collapse the rules down to as small as is reasonably possible without reordering. IPsets will be used eventually.  Default: true
* `ignore`: Set this to an Array of regular expressions that you would like to match in order to preserve running rules. This modifies the behavior of the optimize type.  Do not include the beginning and ending '/' but do include an end or beginning of word marker if appropriate.  Default: []
* `enable_default_rules`: If true, enable the usual set of default deny rules that you would expect to see on most systems.  Default: true

  This uses the following expectations of rule ordering (not enforced):
    * 1 -> ESTABLISHED,RELATED rules.
    * 2-5 -> Standard ACCEPT/DENY rules.
    * 6-10 -> Jumps to other rule sets.
    * 11-20 -> Pure accept rules.
    * 22-30 -> Logging and rejection rules.

* `enable_scanblock`: If true, enable a technique for setting up port-based triggers that will block anyone connecting to the system for an hour after connection to a forbidden port.  Default: false
* `disable`: If true, disable iptables management completely. The build will still happen but nothing will be enforced.  Default: false

### Defined Types

#### `add_all_listen`

This define provides a simple way to allow all protocols to all ports on the target system from a select set of networks.

##### Example

```ruby
iptables::add_all_listen { 'example':
  client_nets => [ '1.2.3.4', '5.6.7.8' ],
}
```

Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -s 1.2.3.4 -j ACCEPT
-A LOCAL-INPUT -s 5.6.7.8 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

#### `add_icmp_listen`
This provides a simple way to allow ICMP ports into the system.

##### Example

Command

```ruby
iptables::add_icmp_listen { "example":
  client_nets => [ "1.2.3.4", "5.6.7.8" ],
  icmp_type => '8'
}
```

Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -p icmp -s 1.2.3.4 --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -p icmp -s 5.6.7.8 --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

#### `add_rules`

This function allows you to add rules to the iptables configuration file.  These rules should be uniquely named.  Rules are added to `/etc/sysconfig/iptables`.

##### Parameters
All parameters are optional, unless otherwise noted.

* `content`: **Required.** The content of the rules that should be added.
* `table`:  Should be the name of the table you are adding to.  Default: 'filter'.
* `first`: Should be set to 'true' if you want to prepend your custom rules.
* `absolute`: Should be set to 'true' if you want the section to be absolutely first or last, depending on the setting of $first.  This is relative and basically places items in alphabetical order.
* `order`: The order in which the rule should appear.  1 is the minimum, 11 is the mean, and 9999999 is the max.

   The following ordering ranges are suggested:
     - **1**     --> ESTABLISHED,RELATED rules.
     - **2-5**   --> Standard ACCEPT/DENY rules.
     - **6-10**  --> Jumps to other rule sets.
     - **11-20** --> Pure accept rules.
     - **22-30** --> Logging and rejection rules.
   These are suggestions and are not enforced.

* `comment`: A comment to prepend to the rule.  Default: ''.
* `header`:  Whether or not to include the line header `'-A LOCAL-INPUT'`.  Default: true.
* `apply_to`: iptables target.  Default: 'auto'.
     - **ipv4** -> iptables
     - **ipv6** -> ip6tables
     - **all**  -> Both
     - **auto** -> Try to figure it out from the rule, will not pick `all`.

##### Example

Command

```ruby
iptables::add_rules { 'example':
  content => '-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp\
  -s 1.2.3.4 --dport 1024:65535 -j ACCEPT'
}
```

Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

#### `add_tcp_stateful_listen`

This provides a simple way to allow TCP ports into the system.

##### Parameters
All parameters are optional, unless otherwise noted.

* `dports`: **Required.** The ports to which to allow entry.  Single ports and port ranges (1:100) are both allowed.  Set the string to 'any' to allow all ports.
* `first`: Should be set to 'true' if you want to prepend your custom rules.
* `absolute`: Should be set to 'true' if you want the section to be absolutely first or last, depending on the setting of $first.  This is relative and basically places items in alphabetical order.
* `order`: The order in which the rule should appear.  1 is the minimum, 11 is the mean, and 9999999 is the max.

   The following ordering ranges are suggested:
     - **1**     --> ESTABLISHED,RELATED rules.
     - **2-5**   --> Standard ACCEPT/DENY rules.
     - **6-10**  --> Jumps to other rule sets.
     - **11-20** --> Pure accept rules.
     - **22-30** --> Logging and rejection rules.
   These are suggestions and are not enforced.

* `apply_to`: iptables target.  Default: 'auto'.
     - **ipv4** -> iptables
     - **ipv6** -> ip6tables
     - **all**  -> Both
     - **auto** -> Try to figure it out from the rule, will not pick `all`.
* `client_nets`: Client networks that should be allowed by this rule.  Set the string to `any` to allow all networks

##### Example

Command

```ruby
iptables::add_tcp_stateful_listen { 'example':
  client_nets => [ '1.2.3.4', '5.6.7.8' ],
  dports => [ '5', '1024:65535' ]
}
```

Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 5 -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 5.6.7.8 --dport 5 -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp -s 5.6.7.8 --dport 1024:65535 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

#### `add_udp_stateful_listen`

This provides a simple way to allow UDP ports into the system.

##### Parameters

* `dports`: **Required.** The ports to which to allow entry.  Single ports and port ranges (1:100) are both allowed.  Set the string to 'any' to allow all ports.
* `first`: Should be set to 'true' if you want to prepend your custom rules.
* `absolute`: Should be set to 'true' if you want the section to be absolutely first or last, depending on the setting of $first.  This is relative and basically places items in alphabetical order.
* `order`: The order in which the rule should appear.  1 is the minimum, 11 is the mean, and 9999999 is the max.

   The following ordering ranges are suggested:
     - **1**     --> ESTABLISHED,RELATED rules.
     - **2-5**   --> Standard ACCEPT/DENY rules.
     - **6-10**  --> Jumps to other rule sets.
     - **11-20** --> Pure accept rules.
     - **22-30** --> Logging and rejection rules.
   These are suggestions and are not enforced.

* `apply_to`: iptables target.  Default: 'auto'.
     - **ipv4** -> iptables
     - **ipv6** -> ip6tables
     - **all**  -> Both
     - **auto** -> Try to figure it out from the rule, will not pick `all`.
* `client_nets`: Client networks that should be allowed by this rule.  Set the string to `any` to allow all networks

##### Example

Command

```ruby
iptables::add_udp_stateful_listen { 'example':
  client_nets => [ '1.2.3.4', '5.6.7.8' ],
  dports => [ '5', '1024:65535' ]
}
```

Output (to /`etc/sysconfig/iptables`)

```bash
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOCAL-INPUT - [0:0]
-A INPUT -j LOCAL-INPUT
-A FORWARD -j LOCAL-INPUT
-A LOCAL-INPUT -p icmp --icmp-type 8 -j ACCEPT
-A LOCAL-INPUT -i lo -j ACCEPT
-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A LOCAL-INPUT -s 1.2.3.4/32 -p udp -m state --state NEW -m multiport --dports 1024:65535,5 -j ACCEPT
-A LOCAL-INPUT -s 5.6.7.8/32 -p udp -m state --state NEW -m multiport --dports 1024:65535,5 -j ACCEPT
-A LOCAL-INPUT -p udp -s 1.2.3.4 --dport 5 -j ACCEPT
-A LOCAL-INPUT -p udp -s 5.6.7.8 --dport 5 -j ACCEPT
-A LOCAL-INPUT -p udp -s 1.2.3.4 --dport 1024:65535 -j ACCEPT
-A LOCAL-INPUT -p udp -s 5.6.7.8 --dport 1024:65535 -j ACCEPT
-A LOCAL-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A LOCAL-INPUT -j LOG --log-prefix "IPT:"
-A LOCAL-INPUT -j DROP
COMMIT
```

## Limitations
* IPv6 support has not been fully tested, use with caution.
* `firewalld` must be disabled.  The module will disable `firewalld` if it is present.
* This module is intended to be used on a Redhat Enterprise Linux-compatible distribution such as EL6 and EL7. However, any distribution that uses the /etc/sysconfig/iptables configuration should function properly (let us know!).

## Development

Please see the [SIMP Contribution Guidelines](https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP).

### Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

```shell
bundle exec rake acceptance
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
