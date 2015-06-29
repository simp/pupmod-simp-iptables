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

  # FIXME: not idempotent on EL7
  it 'should be idempotent' do
  ###  # FIXME: solve this mystery and remove this conditional!
  ###  if ENV['BEAKER_skip_unsolved_mysteries'] == 'yes'
  ###    skip( 'mysteriously fails after first apply (but not second) on EL7' )
  ###  else
  apply_manifest(manifest, :catch_changes => true)
  ###  end
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

### describe 'iptables { service_ensure => stopped }' do
###   let(:manifest) {
###     <<-EOS
###       class { 'iptables':
###         service_ensure => stopped,
###       }
###     EOS
###   }
###
###   it 'should stop the iptables service' do
###     expect(shell("puppet resource service iptables").stdout).to include('stopped')
###   end
### end
###
### describe 'iptables { package_ensure => absent }' do
###   # If the service parameter is absent, removing the package makes each application fail.
###   let(:manifest) {
###     <<-EOS
###       class { 'iptables':
###         package_ensure => absent,
###         service_ensure => stopped,
###       }
###     EOS
###   }
###
###
###   it 'should disable the iptables service' do
###     expect(shell("puppet resource service iptables").stdout).to include("enable => 'false'")
###   end
### end

