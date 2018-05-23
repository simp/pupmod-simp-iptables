require 'spec_helper_acceptance'

test_name "iptables class"

hosts.each do |host|
  describe "iptables class #{host}" do
    before(:context) do
      on(host, 'puppet module list --tree')
    end

    let(:default_manifest) {
      <<-EOS
        class { 'iptables': }

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::listen::tcp_stateful { 'allow_sshd':
          trusted_nets => ['0.0.0.0/0'],
          dports       => 22,
        }
      EOS
    }

    context 'default parameters' do
      it 'should work with no errors' do
        apply_manifest_on(host, default_manifest, :catch_failures => true)
        on(host, 'iptables-save')
      end

      it 'should be idempotent' do
        apply_manifest_on(host, default_manifest, :catch_changes => true)
      end

      it 'should install the iptables package' do
        expect(on(host, "puppet resource package iptables").stdout).to_not include('absent')
      end

      it 'should ensure that the iptables service is running' do
        expect(on(host, "puppet resource service iptables").stdout).to include('running')
      end

      it 'should include a single TCP rule' do
        on(host, "test `iptables-save  | grep ' -p tcp' | wc -l` -eq 1", :acceptable_exit_codes => 0)
      end

      it 'should allow port 22' do
        expect(on(host, "iptables-save  | grep ' -p tcp'").stdout).to include(' --dport', ' 22')
      end
    end

    context 'with scanblock enabled' do
      let(:manifest_with_scanblock_enabled) {
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
      }

     let(:hieradata_with_overrides) {
<<-EOM
---
iptables::rules::scanblock::ip_list_tot : 400
iptables::rules::scanblock::ip_pkt_list_tot : 40
iptables::rules::scanblock::ip_list_hash_size : 256
iptables::rules::scanblock::ip_list_perms : '0644'
EOM
      }

      it 'should work with no errors' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, :catch_failures => true)
        on(host, 'iptables-save')
        on(host, 'ip6tables-save')
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, :catch_changes => true)
      end

      it 'should install and configure xt_recent kernel module using defaults' do
        on(host, "lsmod  | grep xt_recent", :acceptable_exit_codes => 0)

        on(host, "cat /etc/modprobe.d/xt_recent.conf", :acceptable_exit_codes => 0) do
          expected = "options xt_recent ip_list_tot=200 ip_pkt_list_tot=20 ip_list_hash_size=0" +
            " ip_list_perms=0640 ip_list_uid=0 ip_list_gid=0"
          expect(stdout).to eq(expected)
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_tot", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("200\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_pkt_list_tot", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("20\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_hash_size", :acceptable_exit_codes => 0) do
          expect(stdout).to match(/[1-9]+[0-9]/)  # computed value
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_perms", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("416\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_uid", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("0\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_gid", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("0\n")
        end
      end

      it 'should add electric fence rules to iptables' do
        on(host, 'iptables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to match(/-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK/m)
          expect(stdout).to match(/-A ATTACKED -m limit --limit 5\/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED/m)
        end
      end

      it 'should add electric fence rules to ip6tables' do
        os_release = fact_on(host, 'operatingsystemmajrelease')

        on(host, 'ip6tables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to match(/-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK/m)
          expect(stdout).to match(/-A ATTACKED -m limit --limit 5\/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)

          #FIXME Why are these ipv6 iptables rules missing for CentOS6?
          unless os_release == '6'
            expect(stdout).to match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
            expect(stdout).to match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED/m)
          end
        end
      end

      it 'should configure xt_recent kernel module using hieradata overrides' do
        set_hieradata_on(host, hieradata_with_overrides)
        apply_manifest_on(host, manifest_with_scanblock_enabled, :catch_failures => true)

        on(host, "cat /etc/modprobe.d/xt_recent.conf", :acceptable_exit_codes => 0) do
          expected = "options xt_recent ip_list_tot=400 ip_pkt_list_tot=40 ip_list_hash_size=256" +
            " ip_list_perms=0644 ip_list_uid=0 ip_list_gid=0"
          expect(stdout).to eq(expected)
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_tot", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("400\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_pkt_list_tot", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("40\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_hash_size", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("256\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_perms", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("420\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_uid", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("0\n")
        end

        on(host, "cat /sys/module/xt_recent/parameters/ip_list_gid", :acceptable_exit_codes => 0) do
          expect(stdout).to eq("0\n")
        end
      end

      #TODO verify iptables electric fence rules do what is expected!
    end

    context 'with default parameters after scan block had been enabled' do
      it 'should work with no errors' do
        apply_manifest_on(host, default_manifest, :catch_failures => true)
        on(host, 'iptables-save')
        on(host, 'ip6tables-save')
      end

      it 'should only contain single ipv4 rule from default manifest' do
        on(host, "test `iptables-save  | grep ' -p tcp' | wc -l` -eq 1", :acceptable_exit_codes => 0)
        expect(on(host, "iptables-save  | grep ' -p tcp'").stdout).to include(' --dport', ' 22')
        on(host, 'iptables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to_not match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to_not match(/-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK/m)
          expect(stdout).to_not match(/-A ATTACKED -m limit --limit 5\/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to_not match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to_not match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)
          expect(stdout).to_not match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED/m)
        end
      end

      it 'should not contain ipv6 rules from scan block manifest' do
        os_release = fact_on(host, 'operatingsystemmajrelease')

        on(host, 'ip6tables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to_not match(/-A LOCAL-INPUT -m state --state NEW -m comment --comment "SIMP:" -j ATTK_CHECK/m)
          expect(stdout).to_not match(/-A ATTACKED -m limit --limit 5\/min -m comment --comment "SIMP:" -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to_not match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
          expect(stdout).to_not match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)

          #FIXME Why are these ipv6 iptables rules missing for CentOS6?
          unless os_release == '6'
            expect(stdout).to_not match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -m comment --comment "SIMP:" -j DROP/m)
            expect(stdout).to_not match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -m comment --comment "SIMP:" -j ATTACKED/m)
          end
        end
      end
    end
  end
end
