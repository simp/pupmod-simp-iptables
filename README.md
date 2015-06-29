[![Build Status](https://travis-ci.org/pupmod-simp-iptables.svg?branch=master)](https://travis-ci.org/pupmod-simp-iptables)


## Work in Progress

Please excuse us as we transition this code into the public domain.

Downloads, discussion, and patches are still welcome!



## Acceptance tests

To run the system tests, you need [Vagrant](https://www.vagrantup.com/) installed. Then, run:

    bundle exec rake acceptance

Some environment variables may be useful:

    BEAKER_debug=true
    BEAKER_provision=no
    BEAKER_destroy=no
    BEAKER_use_fixtures_dir_for_modules=yes

* The `BEAKER_debug` variable shows the commands being run on the STU and their output.
* `BEAKER_destroy=no` prevents the machine destruction after the tests finish so you can inspect the state.
* `BEAKER_provision=no` prevents the machine from being recreated. This can save a lot of time while you're writing the tests.
* `BEAKER_use_fixtures_dir_for_modules=yes` causes all module dependencies to be loaded from the `spec/fixtures/modules` directory, based on the contents of `.fixtures.yml`.  The contents of this directory are usually populated by `bundle exec rake spec_prep`.  This can be used to run acceptance tests to run on isolated networks.
