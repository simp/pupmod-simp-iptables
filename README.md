[![License](https://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/73/badge)](https://bestpractices.coreinfrastructure.org/projects/73)
[![Puppet Forge](https://img.shields.io/puppetforge/v/simp/iptables.svg)](https://forge.puppetlabs.com/simp/iptables)
[![Puppet Forge Downloads](https://img.shields.io/puppetforge/dt/simp/iptables.svg)](https://forge.puppetlabs.com/simp/iptables)
[![Build Status](https://travis-ci.org/simp/pupmod-simp-iptables.svg)](https://travis-ci.org/simp/pupmod-simp-iptables)

#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with iptables](#setup)
    * [What iptables affects](#what-iptables-affects)
    * [Beginning with iptables](#beginning-with-iptables)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
    * [Data Types](#data-types)
6. [Limitations - OS compatibility, etc.](#limitations)
7. [Development - Guide for contributing to the module](#development)
      * [Acceptance Tests - Beaker env variables](#acceptance-tests)

## Overview

This module provides native types for managing the system IPTables and
IP6Tables as well as convenience defines and general system configuration
capabilities.

The ability to use this module to automatically shim through to firewalld is
optionally supported for legacy systems and modules that are working on
migrating to firewalld support.

## This is a SIMP module

This module is a component of the [System Integrity Management Platform](https://simp-project.com),
a compliance-management framework built on Puppet.

Most SIMP modules actively take advantage of this module when used within the
SIMP ecosystem.

## Module Description

The ``iptables`` module manages all IPTables and IP6Tables rules in an atomic
fashion. All rules are applied only once per puppet agent run during the
application of the last executed ``iptables`` resource.

Applying the rules in this manner ensures that avoid situations where you have
a partially applied IPTables rule set during a failure in your run of puppet
(someone hits ^C, your system runs out of memory, etc...).

The module also takes additional safety measures to attempt to keep your
firewall rules in a consistent state over time to include:

* Rolling back to the last configuration if the application of the new configuration fails
* Rolling back to an 'ssh-only' mode if application of all configurations fail

The goal is to remain in a state where you can be sure that your system is
tightly restricted but also able to be recovered.

Finally, the module works to ensure that services such as OpenStack, Docker,
VirtualBox, etc... can apply their rules without being affected by this module.
The module provides mechanisms to preserve these rules as managed by external
systems based on regular expression matches.

## Setup

### What iptables affects

The module manages the ``iptables`` package, service, and rules.

On systems containing the ``firewalld`` service, it is ensured to be stopped.

### Beginning with iptables

#### I want a basic secure iptables setup

A basic setup with iptables will allow the following:

* ICMP
* Loopback
* SSH
* Established and Related traffic (Return Traffic)

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

The `iptables` module has a set of defined types for adding in new firewall
rules.

```puppet
#open TCP port 443 (HTTPS) and a custom 8443 from any IP Address

iptables::listen::tcp_stateful { 'webserver':
  trusted_nets => ['any'],
  dports => [ 443 , 8443 ]
}

#open UDP port 53 (DNS) from two specific IP addresses

iptables::listen::udp {'DNS':
  trusted_nets => ['192.168.56.55','192.168.56.147'],
  dports      => [ 53 ]
}

#Allow a specific machine full access to this node

iptables::add_all_listen { 'Central Management':
  trusted_nets => ['10.10.35.100'],
}

#Allow a range of ports to be accessible from a specific IP
iptables::listen::tcp_stateful { 'myapp':
  trusted_nets => ['10.10.45.100'],
  dports => ['1024:60000']
}

```

#### This module doesn't cover my specific iptables rule

In the case you need a rule not covered properly by the module, you can use the
``iptables::add_rules`` type to place the exact rule into ``/etc/sysconfig/iptables``.

```puppet
# Inserts a custom rule into IPtables

iptables::rule { 'example':
  content => '-A LOCAL-INPUT -m state --state NEW -m tcp -p tcp\
  -s 1.2.3.4 --dport 1024:65535 -j ACCEPT'
}
```

### Firewalld Mode (experimental)

This module has preliminary support for acting as a pass-through to various
``firewalld`` capabilities using the ``voxpupuli/firewalld`` module.

To put ``firewalld`` into a mode that is consistent with the current
``iptables`` configuration, an ``iptables::firewalld_shim`` class was created.

Using any of the ``iptables::listen::*`` defined types will work seamlessly in
``firewalld`` mode but direct calls to ``iptables::rule`` will fail.

Additionally, calls to any of the native types included in this module will
result in undefined behavior and is not advised.

#### Enabling Firewalld Mode (experimental)

To enable ``firewalld`` mode on supported operating systems, simply set
``iptables::use_firewalld`` to ``true`` via Hiera.

**NOTE: EL 8 systems will enable ``firewalld`` mode by default.**

## Reference

See [REFERENCE.md](./REFERENCE.md)

## Limitations
* IPv6 support has not been fully tested, use with caution
* ``firewalld`` must be disabled if using ``iptables``. The module will disable
  ``firewalld`` if it is present and the module is not in ``firewalld``
  compatibility mode.
* This module is intended to be used on a Redhat Enterprise Linux-compatible
  distribution such as EL6 and EL7. However, any distribution that uses the
  ``/etc/sysconfig/iptables`` configuration should function properly (let us
  know!).

## Development

Please read our [Contribution Guide](https://simp.readthedocs.io/en/stable/contributors_guide/index.html).

### Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/)
installed. Then, run:

```shell
bundle exec rake beaker:suites
```

Some environment variables may be useful:

```shell
BEAKER_debug=true
BEAKER_provision=no
BEAKER_destroy=no
BEAKER_use_fixtures_dir_for_modules=yes
```

* `BEAKER_debug`: show the commands being run on the STU and their output.
* `BEAKER_destroy=no`: prevent the machine destruction after the tests finish
  so you can inspect the state.
* `BEAKER_provision=no`: prevent the machine from being recreated. This can
  save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes`: cause all module dependencies to
  be loaded from the `spec/fixtures/modules` directory, based on the contents
  of `.fixtures.yml`.  The contents of this directory are usually populated by
  `bundle exec rake spec_prep`.  This can be used to run acceptance tests to
  run on isolated networks.
