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

        iptables_rule { 'keep comment':
          table   => 'filter',
          header  => false,
          content => '-A FORWARD -s 1.2.3.4/32 -j ACCEPT'
        }

        iptables_rule { 'drop comment with param':
          include_comment => false,
          table           => 'filter',
          header          => false,
          content         => '-A FORWARD -s 2.3.4.5/32 -j ACCEPT'
        }

        iptables_rule { 'drop comment with empty header':
          table          => 'filter',
          header         => false,
          comment_header => '',
          content        => '-A FORWARD -s 3.4.5.6/32 -j ACCEPT'
        }
      EOS
    }

    it 'should work without errors' do
      apply_manifest_on(host, manifest, :catch_failures => true)
      on(host, 'iptables-save')
      on(host, 'ip6tables-save')
    end

    it 'should be idempotent' do
      apply_manifest_on(host, manifest, :catch_changes => true)
    end

    it 'should have a comment for 1.2.3.4' do
      expect(on(host, 'iptables-save   | grep "1.2.3.4"').output.strip).to eq(
        '-A FORWARD -s 1.2.3.4/32 -m comment --comment "SIMP:" -j ACCEPT'
      )
    end

    it 'should not have a comment for 2.3.4.5' do
      expect(on(host, 'iptables-save   | grep "2.3.4.5"').output.strip).to eq(
        '-A FORWARD -s 2.3.4.5/32 -j ACCEPT'
      )
    end

    it 'should not have a comment for 3.4.5.6' do
      expect(on(host, 'iptables-save   | grep "3.4.5.6"').output.strip).to eq(
        '-A FORWARD -s 3.4.5.6/32 -j ACCEPT'
      )
    end
  end
end
