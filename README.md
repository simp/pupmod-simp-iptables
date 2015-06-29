[![Build Status](https://travis-ci.org/simp/pupmod-simp-iptables.svg?branch=master)](https://travis-ci.org/simp/pupmod-simp-iptables)


## Work in Progress

Please excuse us as we transition this code into the public domain.

Downloads, discussion, and patches are still welcome!


#### Table of Contents

1. [Overview](#overview)
2. [Module Description - What the module does and why it is useful](#module-description)
3. [Setup - The basics of getting started with iptables](#setup)
    * [What iptables affects](#what-iptables-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with iptables](#beginning-with-iptables)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Overview

This sets the system up in a way that will maximally utilize the iptables native types.  Works with EL6 and EL7.

## This is a SIMP module
This module is a component of the [https://github.com/NationalSecurityAgency/SIMP](System Integrity Management Platform), a managed security compliance framework built on Puppet.

This module is optimally designed for use within a larger SIMP ecosystem.  When included within the SIMP ecosystem, security compliance settings will be managed from the Puppet server.


## Module Description

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

If applicable, this section should have a brief description of the technology the module integrates with and what that integration enables. This section should answer the questions: "What does this module *do*?" and "Why would I use it?"

If your module has a range of functionality (installation, configuration, management, etc.) this is the time to mention it.

## Setup

### What iptables affects

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

* A list of files, packages, services, or operations that the module will alter, impact, or execute on the system it's installed on.
* This is a great place to stick any warnings.
* Can be in list or paragraph form.

### Setup Requirements **OPTIONAL**

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

If your module requires anything extra before setting up (pluginsync enabled, etc.), mention it here.

### Beginning with iptables

The very basic steps needed for a user to get the module up and running.

If your most recent release breaks compatibility or requires particular steps for upgrading, you may wish to include an additional section here: Upgrading (For an example, see http://forge.puppetlabs.com/puppetlabs/firewall).

## Usage

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

Put the classes, types, and resources for customizing, configuring, and doing the fancy stuff with your module here.

## Reference

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

Here, list the classes, types, providers, facts, etc contained in your module. This section should include all of the under-the-hood workings of your module so people know what the module is touching on their system but don't need to mess with things. (We are working on automating this message!)

## Limitations

*FIXME:* The text below is boilerplate copy.  Ensure that it is correct and remove this message!

SIMP Puppet modules are generally intended to be used on a Redhat Enterprise Linux-compatible distribution such as EL6 and EL7.  A SIMP module should

## Development

Please see the [https://simp-project.atlassian.net/wiki/display/SD/Contributing+to+SIMP](SIMP Contribution Guidelines).

## Release Notes/Contributors/Etc **Optional**

If you aren't using changelog, put your release notes here (though you should consider using changelog). You may also add any additional sections you feel are necessary or important to include here. Please use the `## ` header.

## Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

    bundle exec rake acceptance

Some environment variables may be useful:

    BEAKER_debug=true
    BEAKER_provision=no
    BEAKER_destroy=no
    BEAKER_use_fixtures_dir_for_modules=yes
    BEAKER_skip_unsolved_mysteries=yes

* The `BEAKER_debug` variable shows the commands being run on the STU and their output.
* `BEAKER_destroy=no` prevents the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no` prevents the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes` causes all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
* `BEAKER_skip_unsolved_mysteries=yes` skips mysterious problems we haven't solved but are "tolerated" prior to release.  *TODO*: This variable should go away by the release of SIMP 6.
