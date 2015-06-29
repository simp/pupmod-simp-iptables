require 'spec_helper_acceptance'

test_name "iptables class"

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
    EOS
  }

  it 'should work with no errors' do
    apply_manifest(manifest, :catch_failures => true)
  end

  it 'should be idempotent' do
    apply_manifest(manifest, :catch_changes => true)
  end

  it 'should install the iptables package' do
    expect(shell("puppet resource package iptables").stdout).to_not include('absent')
  end

  it 'should ensure that the iptables service is running' do
    expect(shell("puppet resource service iptables").stdout).to include('running')
  end

  it 'should include a single TCP rule' do
    shell("test `iptables-save  | grep ' -p tcp' | wc -l` -eq 1", :acceptable_exit_codes => 0)
  end

  it 'should allow port 22' do
    expect(shell("iptables-save  | grep ' -p tcp'").stdout).to include(' --dport', ' 22')
  end
end
