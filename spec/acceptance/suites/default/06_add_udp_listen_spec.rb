require 'spec_helper_acceptance'

test_name 'iptables::listen::udp'

hosts.each do |host|
  describe 'iptables::listen::udp' do
    let(:manifest) {
      <<-EOS
        class { 'iptables': }

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::listen::tcp_stateful { 'allow_sshd':
          trusted_nets => ['0.0.0.0/0'],
          dports       => 22
        }

        iptables::listen::udp { 'test_udp_on_both':
          trusted_nets => ['10.0.2.0/16', 'fe80::/64'],  # Standard Beaker/Vagrant subnet
          dports      => 2222,
          apply_to    => 'all'
        }

        iptables::listen::udp { 'test_udp_on_ipv4':
          trusted_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
          dports      => 4444,
          apply_to    => 'ipv4'
        }

        iptables::listen::udp { 'test_udp_on_ipv6':
          trusted_nets => ['fe80::/64'],  # Standard Beaker/Vagrant subnet
          dports      => 6666,
          apply_to    => 'ipv6'
        }
      EOS
    }

    it 'should work without errors' do
      apply_manifest_on(host, manifest, :catch_failures => true)
      on(host, 'iptables-save')
      on(host, 'ip6tables-save')
    end

    it 'should allow port 2222 for IPv4' do
      on(host, "iptables-save   | grep ' -p udp' | grep -w 2222", :acceptable_exit_codes => 0)
    end

    it 'should allow port 2222 for IPv6' do
      on(host, "ip6tables-save  | grep ' -p udp' | grep -w 2222", :acceptable_exit_codes => 0)
    end

    it 'should allow port 4444 for IPv4' do
      on(host, "iptables-save   | grep ' -p udp' | grep -w 4444", :acceptable_exit_codes => 0)
    end

    it 'should allow port 6666 for IPv6' do
      on(host, "ip6tables-save  | grep ' -p udp' | grep -w 6666", :acceptable_exit_codes => 0)
    end

    it 'should remove OBE tcp rules from iptables::listen::tcp_stateful test' do
      on(host, "iptables-save   | grep ' -p tcp' | grep -w 2222", :acceptable_exit_codes => 1)
      on(host, "ip6tables-save  | grep ' -p tcp' | grep -w 2222", :acceptable_exit_codes => 1)
      on(host, "iptables-save   | grep ' -p tcp' | grep -w 4444", :acceptable_exit_codes => 1)
      on(host, "ip6tables-save  | grep ' -p tcp' | grep -w 6666", :acceptable_exit_codes => 1)
    end
  end
end
