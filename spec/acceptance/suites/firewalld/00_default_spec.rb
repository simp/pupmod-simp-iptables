require 'spec_helper_acceptance'

test_name 'iptables class in firewalld mode'

hosts.each do |host|
  describe "iptables class #{host} in firewalld mode" do
    let(:default_manifest) do
      <<-EOS
        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::listen::tcp_stateful { 'allow_sshd_0.0.0.0':
          trusted_nets => ['0.0.0.0/0'],
          dports       => 22,
        }
      EOS
    end

    let(:hieradata) {{ 'simp_firewalld::enable' => true }}

    context 'default parameters' do
      it 'works with no errors' do
        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, default_manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, default_manifest, catch_changes: true)
      end

      if host[:roles].include?('firewalld')
        it 'has "99_simp" as the default zone' do
          default_zone = on(host, 'firewall-cmd --get-default-zone').output.strip
          expect(default_zone).to eq('99_simp')
        end
      else
        it 'is not running firewalld' do
          svc = YAML.safe_load(on(host, 'puppet resource service firewalld --to_yaml').output)
          expect(svc['service']['firewalld']['ensure']).to match('stopped')
        end

        it 'is running iptables' do
          svc = YAML.safe_load(on(host, 'puppet resource service iptables --to_yaml').output)
          expect(svc['service']['iptables']['ensure']).to match('running')
        end
      end
    end

    context 'TCP listen' do
      let(:manifest) do
        <<-EOM
          #{default_manifest}

          iptables::listen::tcp_stateful { 'allow_tcp_listen':
            trusted_nets => ['1.2.3.4/24', '3.4.5.6', '5.6.7.8/32'],
            dports       => 1234
          }
        EOM
      end

      it 'works with no errors' do
        set_hieradata_on(host, hieradata)
        apply_manifest_on(host, manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest, catch_changes: true)
      end
    end

    context 'UDP listen' do
      let(:manifest) do
        <<-EOM
          #{default_manifest}

          iptables::listen::udp { 'allow_udp_listen':
            trusted_nets => ['2.3.4.5/8', '3.4.5.6', '5.6.7.8/32'],
            dports       => 2345
          }
        EOM
      end

      it 'works with no errors' do
        apply_manifest_on(host, manifest, catch_failures: true)
      end

      it 'is idempotent' do
        apply_manifest_on(host, manifest, catch_changes: true)
      end
    end
  end
end
