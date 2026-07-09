# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this module does

`simp-iptables` is a SIMP Puppet module that **safely manages IPTables and
IP6Tables firewall rules** on Enterprise Linux systems. Its defining feature is
that it applies the entire ruleset **atomically** — all `iptables_rule`
resources in the catalog are collected and written out exactly once, during the
apply of the *last* `iptables_rule` in the run, so the system is never left with
a half-applied ruleset if the Puppet run is interrupted (`README.md`;
`lib/puppet/provider/iptables_rule/manage.rb`). It also installs
fail-safe startup/retry init scripts and keeps a `.bak` of the previous config
so a broken ruleset can roll back rather than lock you out
(`manifests/service.pp`, `lib/puppet/provider/iptables_optimize/optimize.rb`).

The module can also **shim to `firewalld`** (via the optional `simp/simp_firewalld`
module). This is the **default** behavior: `iptables::use_firewalld` defaults to
`true` (`manifests/init.pp`), so on a stock apply the module delegates to
`simp_firewalld` and the native iptables management path is *not* used. The
module docstring "highly recommends" firewalld mode where supported
(`manifests/init.pp`).

The module is also conflict-aware: `iptables::enable` defaults to the SIMP
option `simp_options::firewall`. If that option is `false` the class refuses to
manage IPTables and warns; if `enable` is `'ignore'` it stops managing IPTables
entirely (`manifests/init.pp`).

### Business logic

Public entry points are the `iptables` class plus a set of defines
(`iptables::rule`, `iptables::ports`, `iptables::listen::*`) and one deprecated
function. Everything under `iptables::install`, `iptables::service`, and
`iptables::rules::*` is `assert_private()`'d.

- **`iptables` (`manifests/init.pp`)** — public class. Key parameters:
  - `$enable` (`Variant[Enum['ignore','firewalld'],Boolean]`) — defaults to
    `simplib::lookup('simp_options::firewall', {'default_value' => true})`
    (`init.pp`). `'ignore'` short-circuits the whole class body
    (`init.pp`).
  - `$use_firewalld` (`Boolean`, default `true`, `init.pp`) — the master
    switch between the firewalld path and the native path.
  - `$ensure` — `simplib::lookup('simp_options::package_ensure', {'default_value' => 'installed'})`
    (`init.pp`).
  - `$ipv6` (default `true`), `$optimize_rules` (default `true`),
    `$precise_match` (default `false`), `$default_rules` (default `true`),
    `$scanblock` (default `false`), `$prevent_localhost_spoofing` (default
    `true`), `$ports` (`Optional[Hash]`, default `undef`)
    (`init.pp`).

  Control flow (`init.pp`):
  - Always `contain 'iptables::install'` when not ignoring (`init.pp`).
  - **firewalld branch** (`init.pp`): asserts the optional dependency
    `simp/simp_firewalld`, `include 'simp_firewalld'`, and — only if `$ports`
    is set — declares `iptables::ports { 'firewalld': }`.
  - **native branch** (`init.pp`): `contain`s `iptables::service`,
    `iptables::rules::base` (if `$default_rules`), `iptables::rules::scanblock`
    (if `$scanblock`), `iptables::rules::prevent_localhost_spoofing` (if
    `$prevent_localhost_spoofing`), and always `iptables::rules::default_drop`.
    Manages `/etc/sysconfig/iptables` (and `/etc/sysconfig/ip6tables` when
    `$ipv6 and $facts['ipv6_enabled']`) and declares the `iptables_optimize` /
    `ip6tables_optimize` custom resources against those files.
- **`iptables::install` (`manifests/install.pp`)** — installs
  `$ipv4_package`/`$ipv6_package` (both `String[1]`, **no default in the
  manifest** — supplied entirely from module data, `install.pp`). ipv6
  package installed only when `$iptables::ipv6 and $facts['ipv6_enabled']`.
- **`iptables::service` (`manifests/service.pp`)** — manages `iptables` /
  `ip6tables` services plus `*-retry` fail-safe services, deploys the init
  scripts from `files/`, and force-stops `firewalld` (`service.pp`).
  Service `restart` command falls back to restoring the `.bak` file and exiting
  3 on failure (`service.pp`).
- **`iptables::rule` (`manifests/rule.pp`)** — the low-level "add a raw rule"
  define. **In firewalld mode it does nothing but emit a `warning` notify**
  telling you to use `simp_firewalld::rule` instead (`rule.pp`).
- **`iptables::ports` (`manifests/ports.pp`)** — hash-driven port opener; parses
  a `ports` hash (with optional `defaults` sub-hash) and fans out to
  `iptables::listen::tcp_stateful` / `iptables::listen::udp` per protocol;
  `fail()`s on an unknown proto (`ports.pp`).
- **`iptables::listen::{tcp_stateful,udp,all,icmp}`** — convenience defines.
  Each branches on `$iptables::use_firewalld`: firewalld mode emits a
  `simp_firewalld::rule`, native mode emits an `iptables_rule` built from an ERB
  template (`manifests/listen/tcp_stateful.pp`, and siblings).
- **`iptables::rules::base`** — the default deny/allow ruleset (established/
  related, loopback, ping, drop broadcast/multicast, log, drop-all), using the
  suggested (non-enforced) order ranges (`manifests/rules/base.pp`).
- **`iptables::rules::default_drop`** — sets default chain policy on
  filter INPUT/FORWARD/OUTPUT via `iptables_default_policy`; unset params leave
  the policy unchanged (`manifests/rules/default_drop.pp`).
- **`iptables::rules::scanblock` + `iptables::rules::mod_recent`** — the
  "electric fence" that bans hosts hitting forbidden ports, using the
  `xt_recent` kernel module (`manifests/rules/scanblock.pp`,
  `manifests/rules/mod_recent.pp`).
- **`iptables::use_firewalld` (`functions/use_firewalld.pp`)** — **DEPRECATED**;
  calls `deprecation()` on every invocation (`use_firewalld.pp`). Not used
  by the manifests.

### Custom types / providers / functions (under `lib/`)

This is a large module whose real logic lives in Ruby, not the manifests. All of
the following are **provided by this module itself**, not by dependencies.

- **`iptables_rule`** type (`lib/puppet/type/iptables_rule.rb`) + `manage`
  provider (`lib/puppet/provider/iptables_rule/manage.rb`, 414 lines — the most
  complex file). Authoritative, **atomic** rule management. The provider counts
  every `iptables_rule` in the catalog and only collates + writes the two target
  files (`/etc/sysconfig/.iptables_puppet`, `/etc/sysconfig/.ip6tables_puppet`,
  mode `0600`) on the final resource's run (`manage.rb`). Supports
  optional DNS resolution of `-s`/`-d` hostnames (`resolve`, default true), auto
  IP-family detection (`apply_to => auto`), and kernel-version-gated table
  support (`manage.rb`).
- **`iptables_optimize`** type (`lib/puppet/type/iptables_optimize.rb`) +
  `optimize` provider (`lib/puppet/provider/iptables_optimize/optimize.rb`), and
  its near-identical IPv6 twin **`ip6tables_optimize`**
  (`lib/puppet/type/ip6tables_optimize.rb`, provider inherits from the v4
  provider, `.../ip6tables_optimize/optimize.rb`). These are the
  idempotency-driven "optimize" resources: they compare the desired ruleset
  against the running ruleset, preserve externally-managed rules matched by the
  `ignore` regexes, optionally collapse consecutive rules into `multiport`
  matches, and write a `.bak` before applying. The heavy lifting (rule modeling,
  dedup, multiport collapse ≤15 ports, reporting) lives in
  `lib/puppetx/simp/iptables.rb` (561 lines) and
  `lib/puppetx/simp/iptables/rule.rb` (173 lines).
- **`iptables_default_policy`** type (`lib/puppet/type/iptables_default_policy.rb`)
  + `enforce` provider — sets ACCEPT/DROP default policy on filter
  INPUT/FORWARD/OUTPUT for v4 and v6.
- **`xt_recent`** type (`lib/puppet/type/xt_recent.rb`) + `set` provider —
  manages the `xt_recent` kernel-module tunables via `/proc/net/xt_recent`.
- **`iptables::slice_ports`** function
  (`lib/puppet/functions/iptables/slice_ports.rb`) — splits a port list into
  groups of ≤ `max_length` slots (a range counts as 2 slots); raises if
  `max_length == 1` and a range is present (`slice_ports.rb`).

### Gotchas / non-obvious details

- **firewalld is the default path.** `iptables::use_firewalld` defaults to `true`
  (`init.pp`), so a stock `include iptables` delegates to `simp_firewalld`
  and never touches the native iptables types. To exercise the native path you
  must set `iptables::use_firewalld: false` (as `data/os/Amazon-2.yaml` does
  for Amazon 2).
- **`iptables::rule` is a no-op in firewalld mode** — it only warns; it does not
  create a rule (`rule.pp`). Use `simp_firewalld::rule` there.
- **Rules apply atomically, once per run.** The `iptables_rule` provider batches
  every rule and writes only on the last resource
  (`manage.rb`). Do not expect a single `iptables_rule` to apply in
  isolation.
- **`iptables_optimize` and `ip6tables_optimize` are copy-paste duplicates.**
  The type file opens with a comment admitting this: "there's no 'good' way of
  doing type inheritance ... This should be fixed in the future"
  (`lib/puppet/type/ip6tables_optimize.rb`). Keep both in sync when editing.
- **Known-suspect Ruby in `lib/`** (verify against current behavior/tests before
  touching): the `ignore`-param munge error message in both optimize
  types references an undefined `key`/`value[key]`
  (`ip6tables_optimize.rb`, `iptables_optimize.rb`); and
  `lib/puppet/provider/ip6tables_optimize/optimize.rb` assigns
  `@ipt_config[:enabled]` what looks like a 2-element array via a stray trailing
  comma. Do not "fix" these blind — confirm against the running behavior/tests
  first.
- **`mod_recent` reloads the kernel module** with a documented caveat: changing
  `/etc/modprobe.d/xt_recent.conf` after the module is loaded can kernel-panic
  if buffer sizes *increase*, so it `rmmod`/`modprobe`s `xt_recent`
  (`manifests/rules/mod_recent.pp`).
- **No `data/common.yaml`.** `hiera.yaml` lists a `common.yaml` tier
  (`hiera.yaml`) but the file does not exist — hiera simply skips it. All
  module data is per-OS under `data/os/`, and every supported OS file sets the
  package to `iptables-services`. `iptables::install`'s package params have **no
  manifest default**, so on an OS not covered by `data/os/` the class would fail
  to compile for lack of a package name.
- **`iptables::use_firewalld` (the function) is deprecated** and unused by the
  manifests; it warns on every call (`functions/use_firewalld.pp`).
- **ipv6 management is fact-gated.** ip6tables files/services/rules are managed
  only when `$iptables::ipv6 and $facts['ipv6_enabled']`
  (`init.pp`, `install.pp`, `service.pp`).

## The `simp_options` / `simplib::lookup` seam

This module does route SIMP feature toggles through the `simp_options` seam via
`simplib::lookup`. All calls (in the manifests):

| Location | Key | `default_value` |
|----------|-----|-----------------|
| `manifests/init.pp` | `simp_options::firewall` | `true` |
| `manifests/init.pp` | `simp_options::package_ensure` | `'installed'` |
| `manifests/listen/tcp_stateful.pp` | `simp_options::trusted_nets` | `['127.0.0.1']` |
| `manifests/listen/udp.pp` | `simp_options::trusted_nets` | `['127.0.0.1']` |
| `manifests/listen/all.pp` | `simp_options::trusted_nets` | `['127.0.0.1']` |
| `manifests/listen/icmp.pp` | `simp_options::trusted_nets` | `['127.0.0.1']` |

Keep routing SIMP feature toggles through `simplib::lookup('simp_options::*', {
'default_value' => ... })` with an explicit default rather than assuming
`simp_options` is included. Note `simp/simp_options` is **not** a declared
dependency in `metadata.json`; the `simplib::lookup` function comes from
`simp/simplib`, and `simp_options` appears only as a fixture (`.fixtures.yml`).

## Dependencies

Module dependencies (from `metadata.json`):

- `puppetlabs/stdlib` `>= 8.0.0 < 10.0.0` (`metadata.json`) — provides
  `stdlib::ensure_packages`, `str2bool`.
- `simp/simplib` `>= 4.9.0 < 6.0.0` (`metadata.json`) — provides
  `simplib::lookup`, `simplib::assert_metadata`,
  `simplib::assert_optional_dependency`, `simplib::caller`, the
  `Simplib::Port` / `Simplib::Netlist` data types, `PuppetX::SIMP::Simplib`
  (used by the optimize provider's `human_sort`), and facts such as
  `ipv6_enabled` and `simplib__firewalls`.

Optional dependency (from `metadata.json` `simp.optional_dependencies`,
`metadata.json`):

- `simp/simp_firewalld` `>= 0.1.3 < 3.0.0` — the firewalld shim; asserted at
  runtime with `simplib::assert_optional_dependency` whenever `use_firewalld` is
  true.

Fixture-only dependencies (from `.fixtures.yml`, present for test compilation):
`augeas_core`, `firewalld`, `simp_firewalld`, `simp_options`, `simplib`,
`stdlib`.

Runtime requirement (from `metadata.json` `requirements`): `openvox
>= 8.0.0 < 9.0.0` (`metadata.json`).

Supported OS matrix (from `metadata.json`): CentOS 9/10; RedHat 8/9/10;
OracleLinux 8/9/10; Rocky 8/9/10; AlmaLinux 8/9/10.

## Repository layout

- `manifests/init.pp` — the `iptables` public class and top-level control flow.
- `manifests/{install,service}.pp` — private package/service management.
- `manifests/rule.pp`, `manifests/ports.pp` — public rule/port defines.
- `manifests/listen/{tcp_stateful,udp,all,icmp}.pp` — public "open access"
  defines (dual firewalld/native).
- `manifests/rules/{base,default_drop,scanblock,mod_recent,prevent_localhost_spoofing}.pp`
  — private rule bundles.
- `functions/use_firewalld.pp` — deprecated Puppet-language function.
- `types/{applyto,destport,portrange}.pp` — `Iptables::ApplyTo`,
  `Iptables::DestPort`, `Iptables::PortRange` data types.
- `lib/puppet/type/`, `lib/puppet/provider/` — the five custom types
  (`iptables_rule`, `iptables_optimize`, `ip6tables_optimize`,
  `iptables_default_policy`, `xt_recent`) and their providers.
- `lib/puppet/functions/iptables/slice_ports.rb` — the `iptables::slice_ports`
  function.
- `lib/puppetx/simp/iptables.rb`, `lib/puppetx/simp/iptables/rule.rb` — the
  in-memory iptables ruleset model that powers the optimize providers.
- `templates/*.erb` — rule-content templates used by the listen defines.
- `files/{iptables,ip6tables,iptables-retry,ip6tables-retry}` — the init /
  fail-safe startup scripts deployed by `iptables::service`.
- `data/os/*.yaml`, `hiera.yaml` — module data (per-OS package names; Amazon-2
  also sets `use_firewalld: false`). No `data/common.yaml`.
- `spec/classes/`, `spec/defines/`, `spec/functions/`, `spec/unit/` —
  rspec-puppet and Ruby unit tests; `spec/acceptance/suites/{default,firewalld}`
  — beaker acceptance suites, with nodesets under
  `spec/acceptance/nodesets/`.
- `REFERENCE.md` — generated Puppet Strings reference.
- **Acceptance runs in CI:** `.github/workflows/pr_tests.yml` has an
  `acceptance` job whose matrix of docker nodesets (alma/centos/oel/rocky 8-10)
  runs `bundle exec rake beaker:suites[firewalld,<node>]`
  (`pr_tests.yml`).

## Common commands

```sh
# Install dependencies
bundle install

# Run all unit tests
bundle exec rake spec

# Run one spec file
bundle exec rspec spec/classes/init_spec.rb

# Run unit tests in parallel (as CI does)
bundle exec rake parallel_spec

# Puppet syntax + lint
bundle exec rake syntax
bundle exec rake lint

# Ruby lint (custom types/providers/functions)
bundle exec rake rubocop

# Regenerate REFERENCE.md from puppet-strings docstrings
puppet strings generate --format markdown --out REFERENCE.md

# Run a beaker acceptance suite (as CI does)
bundle exec rake beaker:suites[firewalld,docker_alma9]
bundle exec rake beaker:suites[default]
```

Relevant gem pins (from `Gemfile`): `puppetlabs_spec_helper ~> 8.0.0`,
`simp-rake-helpers ~> 5.25.0`, `simp-rspec-puppet-facts ~> 4.0.0`,
`simp-beaker-helpers ~> 2.0.0`, `rubocop ~> 1.88.0`. The Gemfile pulls in
**both** the `openvox` and `puppet` gems until the puppet dependency is dropped
elsewhere (`Gemfile`); the tested version range is `>= 8 < 9`.

## Conventions

- Preserve the `@summary` / `@param` puppet-strings docstrings on classes,
  defines, and the function — they drive `REFERENCE.md`. Regenerate
  `REFERENCE.md` after changing docs or parameters.
- Keep the package names in module data (`data/os/*.yaml`), not hard-coded in
  `iptables::install`.
- Continue routing SIMP feature toggles through
  `simplib::lookup('simp_options::*', { 'default_value' => ... })` rather than
  assuming `simp_options` is included.
- Guard the `simp_firewalld` integration with `simplib::assert_optional_dependency`
  and the `use_firewalld` check, as the manifests do — don't hard-`include` the
  optional module.
- When editing the optimize types/providers, remember `iptables_optimize` and
  `ip6tables_optimize` are duplicated by hand — change both.
- `Gemfile`, `.github/workflows/pr_tests.yml`, `.gitignore`, `.pdkignore`, and
  the other baseline files carry a **puppetsync** notice — they are
  baseline-managed and the next sync overwrites local edits. Push changes to
  those files upstream to the baseline, not here.
- Match the existing 2-space Puppet indentation and aligned-arrow parameter
  style used throughout `manifests/`.
