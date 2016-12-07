require 'spec_helper_acceptance'

test_name "iptables class"

['6', '7'].each do |os_major_version|
  describe "iptables class for CentOS #{os_major_version}" do
    let(:host) {only_host_with_role( hosts, "server#{os_major_version}" ) }

    context 'default parameters' do
      let(:manifest) {
      <<-EOS
        class { 'iptables': }

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::add_tcp_stateful_listen { 'allow_sshd':
          trusted_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
          dports      => '22',
        }
      EOS
      }

      it 'should work with no errors' do
        apply_manifest_on(host, manifest, :catch_failures => true)
      end

      it 'should be idempotent' do
        apply_manifest_on(host, manifest, :catch_changes => true)
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
        class { 'iptables': enable_scanblock => true}

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::add_tcp_stateful_listen { 'allow_sshd':
          trusted_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
          dports      => '22',
        }
      EOS
      }

     let(:hieradata_with_overrides) {
<<-EOM
---
iptables::xt_recent::ip_list_tot : '400'
iptables::xt_recent::ip_pkt_list_tot : '40'
iptables::xt_recent::ip_list_hash_size : '256'
iptables::xt_recent::ip_list_perms : '0644'
EOM
      }

      it 'should work with no errors' do
        apply_manifest_on(host, manifest_with_scanblock_enabled, :catch_failures => true)
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

      it 'should add electric fence rules to iptables and ip6tables' do
        on(host, 'iptables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -j DROP/m)
          expect(stdout).to match(/-A LOCAL-INPUT -m state --state NEW -j ATTK_CHECK/m)
          expect(stdout).to match(/-A ATTACKED -m limit --limit 5\/min -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -j DROP/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -j ATTACKED/m)
        end

        on(host, 'ip6tables-save',  :acceptable_exit_codes => 0) do
          expect(stdout).to match(/-A LOCAL-INPUT -m state --state NEW -j ATTK_CHECK/m)
          expect(stdout).to match(/-A ATTACKED -m limit --limit 5\/min -j LOG --log-prefix \"IPT: \(Rule ATTACKED\): \"/m)
          expect(stdout).to match(/-A ATTACKED -m recent --set --name BANNED .*--rsource -j DROP/m)
          expect(stdout).to match(/-A ATTK_CHECK -m recent --set --name ATTK .*--rsource/m)

          #FIXME Why are these ipv6 iptables rules missing for CentOS6?
          unless os_major_version == '6'
            expect(stdout).to match(/-A LOCAL-INPUT -m recent --update --seconds 3600 --name BANNED .*--rsource -j DROP/m)
            expect(stdout).to match(/-A ATTK_CHECK -m recent --update --seconds 60 --hitcount 2 --name ATTK .*--rsource -j ATTACKED/m)
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

      #TODO verify iptable electric fence rules do what is expected!
    end
  end
end
