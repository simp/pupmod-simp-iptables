require 'spec_helper_acceptance'

test_name "iptables::add_tcp_stateful_listen"

describe 'iptables' do
  let(:manifest) {
    <<-EOS
      class { 'iptables': }

      # Ironically, if iptables applies correctly, its default settings will
      # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
      # define a rule that permit SSH access from the standard Vagrant subnets:
      iptables::add_tcp_stateful_listen { 'allow_sshd':
        client_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
        dports      => '22',
      }


      iptables::add_tcp_stateful_listen { 'test_tcp_on_both':
        client_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
        dports      => '2222',
        apply_to    => 'all',
      }

      iptables::add_tcp_stateful_listen { 'test_tcp_on_ipv4':
        client_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
        dports      => '4444',
        apply_to    => 'ipv4',
      }

      ### iptables::add_tcp_stateful_listen { 'test_tcp_on_ipv6':
      ###   client_nets => ['10.0.2.0/16'],  # Standard Beaker/Vagrant subnet
      ###   dports      => '6666',
      ###   apply_to    => 'ipv6',
      ### }
    EOS
  }

  it 'should work without errors' do
    apply_manifest(manifest, :catch_failures => true)
  end

  it 'should allow port 2222 for IPv4' do
    shell("iptables-save   | grep ' -p tcp' | grep -w 2222", :acceptable_exit_codes => 0)
  end

  ### it 'should allow port 2222 for IPv6' do
  ###   shell("ip6tables-save  | grep ' -p tcp' | grep -w 2222", :acceptable_exit_codes => 0)
  ### end

  it 'should allow port 4444 for IPv4' do
    shell("iptables-save   | grep ' -p tcp' | grep -w 4444", :acceptable_exit_codes => 0)
  end

  ### it 'should allow port 6666 for IPv6' do
  ###   shell("ip6tables-save  | grep ' -p tcp' | grep -w 6666", :acceptable_exit_codes => 0)
  ### end
end

