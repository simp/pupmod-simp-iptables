require 'spec_helper_acceptance'

test_name 'iptables class'

hosts.each do |host|
  unless host[:roles].include?('iptables')
    describe 'iptables' do
      context host.to_s do
        it 'skips default test suite' do
          true
        end
      end
    end

    next
  end

  describe "iptables class #{host}" do
    before(:context) do
      on(host, 'puppet module list --tree')
    end

    let(:default_manifest) do
      <<-EOS
        class { 'iptables': }

        iptables::listen::tcp_stateful { 'allow_sshd':
          trusted_nets => ['0.0.0.0/0'],
          dports       => 22,
        }
      EOS
    end

    context 'default parameters' do
      it 'works with no errors' do
        apply_manifest_on(host, default_manifest, catch_failures: true)
        on(host, 'iptables-save')
      end

      it 'is idempotent' do
        apply_manifest_on(host, default_manifest, catch_changes: true)
      end

      it 'installs the iptables package' do
        expect(on(host, 'puppet resource package iptables').stdout).not_to include('absent')
      end

      it 'ensures that the iptables service is running' do
        expect(on(host, 'puppet resource service iptables').stdout).to include('running')
      end

      it 'includes a single TCP rule' do
        on(host, "test `iptables-save  | grep ' -p tcp' | wc -l` -eq 1", acceptable_exit_codes: 0)
      end

      it 'allows port 22' do
        expect(on(host, "iptables-save  | grep ' -p tcp'").stdout).to include(' --dport', ' 22')
      end
    end

    context 'with scanblock enabled' do
      let(:manifest_with_scanblock_enabled) do
        <<-EOS
        class { 'iptables': scanblock => true}

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::listen::tcp_stateful { 'allow_sshd':
          trusted_nets => ['0.0.0.0/0'],  # Standard Beaker/Vagrant subnet
          dports       => 22
        }
      EOS
      end

      let(:hieradata_with_overrides) do
        <<-EOM
---
iptables::rules::scanblock::ip_list_tot : 400
iptables::rules::scanblock::ip_pkt_list_tot : 40
iptables::rules::scanblock::ip_list_hash_size : 256
iptables::rules::scanblock::ip_list_perms : '0644'
EOM
      end

      it 'works with no errors' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, catch_failures: true)
        on(host, 'iptables-save')
        on(host, 'ip6tables-save')
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, catch_changes: true)
      end

      it 'installs and configure xt_recent kernel module using defaults' do
        on(host, 'lsmod  | grep xt_recent', acceptable_exit_codes: 0)

        on(host, 'cat /etc/modprobe.d/xt_recent.conf', acceptable_exit_codes: 0) do
          expected = 'options xt_recent ip_list_tot=200 ip_pkt_list_tot=20 ip_list_hash_size=0' \
                     ' ip_list_perms=0640 ip_list_uid=0 ip_list_gid=0'
          expect(stdout).to eq(expected)
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_tot', acceptable_exit_codes: 0) do
          expect(stdout).to eq("200\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_pkt_list_tot', acceptable_exit_codes: 0) do
          expect(stdout).to eq("20\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_hash_size', acceptable_exit_codes: 0) do
          expect(stdout).to match(%r{[1-9]+[0-9]}) # computed value
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_perms', acceptable_exit_codes: 0) do
          expect(stdout).to eq("416\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_uid', acceptable_exit_codes: 0) do
          expect(stdout).to eq("0\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_gid', acceptable_exit_codes: 0) do
          expect(stdout).to eq("0\n")
        end
      end

      it 'adds electric fence rules to iptables' do
        on(host, 'iptables-save', acceptable_exit_codes: 0) do
          expect(stdout).to match(%r{-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).to match(%r{-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK}m)
          expect(stdout).to match(%r{-A ATTACKED -m limit --limit 5/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"}m)
          expect(stdout).to match(%r{-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).to match(%r{-A ATTK_CHECK -m recent --set --name ATTK .*--rsource}m)
          expect(stdout).to match(%r{-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED}m)
        end
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, catch_changes: true)
      end

      it 'adds electric fence rules to ip6tables' do
        fact_on(host, 'operatingsystemmajrelease')

        on(host, 'ip6tables-save', acceptable_exit_codes: 0) do
          expect(stdout).to match(%r{-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK}m)
          expect(stdout).to match(%r{-A ATTACKED -m limit --limit 5/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"}m)
          expect(stdout).to match(%r{-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).to match(%r{-A ATTK_CHECK -m recent --set --name ATTK .*--rsource}m)

          expect(stdout).to match(%r{-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).to match(%r{-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED}m)
        end
      end

      it 'configures xt_recent kernel module using hieradata overrides' do
        set_hieradata_on(host, hieradata_with_overrides)

        # FIXME: On at least Amazon Linux 2, this will fail with a number of errors:
        # Error: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_list_tot
        # Error: /Stage[main]/Iptables::Rules::Mod_recent/Xt_recent[/sys/module/xt_recent/parameters]/ip_list_tot: change from '200' to 400 failed: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_list_tot
        # Error: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_pkt_list_tot
        # Error: /Stage[main]/Iptables::Rules::Mod_recent/Xt_recent[/sys/module/xt_recent/parameters]/ip_pkt_list_tot: change from '20' to 40 failed: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_pkt_list_tot
        # Error: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_list_perms
        # Error: /Stage[main]/Iptables::Rules::Mod_recent/Xt_recent[/sys/module/xt_recent/parameters]/ip_list_perms: change from '0640' to '0644' failed: Input/output error @ fptr_finalize_flush - /sys/module/xt_recent/parameters/ip_list_perms
        pending 'https://github.com/simp/pupmod-simp-iptables/issues/129'
        apply_manifest_on(host, manifest_with_scanblock_enabled, catch_failures: false)

        # Reboot to ensure that the settings change takes effect
        host.reboot

        apply_manifest_on(host, manifest_with_scanblock_enabled, catch_failures: true)

        on(host, 'cat /etc/modprobe.d/xt_recent.conf', acceptable_exit_codes: 0) do
          expected = 'options xt_recent ip_list_tot=400 ip_pkt_list_tot=40 ip_list_hash_size=256' \
                     ' ip_list_perms=0644 ip_list_uid=0 ip_list_gid=0'
          expect(stdout).to eq(expected)
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_tot', acceptable_exit_codes: 0) do
          expect(stdout).to eq("400\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_pkt_list_tot', acceptable_exit_codes: 0) do
          expect(stdout).to eq("40\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_hash_size', acceptable_exit_codes: 0) do
          expect(stdout).to eq("256\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_perms', acceptable_exit_codes: 0) do
          expect(stdout).to eq("420\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_uid', acceptable_exit_codes: 0) do
          expect(stdout).to eq("0\n")
        end

        on(host, 'cat /sys/module/xt_recent/parameters/ip_list_gid', acceptable_exit_codes: 0) do
          expect(stdout).to eq("0\n")
        end
      end

      # TODO: verify iptables electric fence rules do what is expected!
    end

    context 'with default parameters after scan block had been enabled' do
      it 'works with no errors' do
        apply_manifest_on(host, default_manifest, catch_failures: true)
        on(host, 'iptables-save')
        on(host, 'ip6tables-save')
      end

      it 'onlies contain single ipv4 rule from default manifest' do
        on(host, "test `iptables-save  | grep ' -p tcp' | wc -l` -eq 1", acceptable_exit_codes: 0)
        expect(on(host, "iptables-save  | grep ' -p tcp'").stdout).to include(' --dport', ' 22')
        on(host, 'iptables-save', acceptable_exit_codes: 0) do
          expect(stdout).not_to match(%r{-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).not_to match(%r{-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK}m)
          expect(stdout).not_to match(%r{-A ATTACKED -m limit --limit 5/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"}m)
          expect(stdout).not_to match(%r{-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).not_to match(%r{-A ATTK_CHECK -m recent --set --name ATTK .*--rsource}m)
          expect(stdout).not_to match(%r{-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED}m)
        end
      end

      it 'does not contain ipv6 rules from scan block manifest' do
        fact_on(host, 'operatingsystemmajrelease')

        on(host, 'ip6tables-save', acceptable_exit_codes: 0) do
          expect(stdout).not_to match(%r{-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK}m)
          expect(stdout).not_to match(%r{-A ATTACKED -m limit --limit 5/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"}m)
          expect(stdout).not_to match(%r{-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).not_to match(%r{-A ATTK_CHECK -m recent --set --name ATTK .*--rsource}m)

          expect(stdout).not_to match(%r{-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP}m)
          expect(stdout).not_to match(%r{-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED}m)
        end
      end
    end
  end
end
