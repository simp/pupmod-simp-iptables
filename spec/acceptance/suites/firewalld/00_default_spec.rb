require 'spec_helper_acceptance'

test_name "iptables class in firewalld mode"

hosts.each do |host|
  next unless host[:roles].include?('firewalld')

  describe "iptables class #{host} in firewalld mode" do
    let(:default_manifest) {
      <<-EOS
        class { 'iptables':
          enable => 'firewalld'
        }

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
      end

      it 'should be idempotent' do
        apply_manifest_on(host, default_manifest, :catch_changes => true)
      end

      if host.file_exist?('/etc/firewalld')
        it 'should have "simp" as the default zone' do
          default_zone = on(host, 'firewall-cmd --get-default-zone').output.strip
          expect(default_zone).to match('simp')
        end

        it 'should have the "simp_tcp_allow_sshd" service in the "simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd')
        end
      else
        it 'should not be running firewalld' do
          svc = YAML.load(on(host, 'puppet resource service firewalld --to_yaml').output)
          expect(svc['service']['firewalld']['ensure']).to match('stopped')
        end

        it 'should be running iptables' do
          svc = YAML.load(on(host, 'puppet resource service iptables --to_yaml').output)
          expect(svc['service']['iptables']['ensure']).to match('running')
        end
      end
    end

    if host.file_exist?('/etc/firewalld')
      context 'TCP listen' do
        let(:manifest) {
          <<-EOM
            #{default_manifest}

            iptables::listen::tcp_stateful { 'allow_tcp_listen':
              trusted_nets => ['1.2.3.4/24', '3.4.5.6', '5.6.7.8/32'],
              dports       => 1234
            }
          EOM
        }

        it 'should work with no errors' do
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, :catch_changes => true)
        end

        it 'should have the "simp_tcp_allow_sshd" service in the "simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd')
        end

        it 'should have an appropriate ruleset configured' do
          rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=simp').output.strip.lines

          target_ruleset = rulesets.grep(%r("simp_tcp_allow_tcp_listen"))

          expect(target_ruleset.size).to eq(2)

          expect(target_ruleset).to include(match(%r{1\.2\.3\.0/24}))

          ruleset_ipset = target_ruleset.grep(/ipset=/).first.match('ipset="(.+?)"')[1]

          expect(ruleset_ipset).to_not be_empty

          ipset = on(host, "firewall-cmd --info-ipset=#{ruleset_ipset}").output

          ipset = ipset.lines.delete_if{|x| x !~ /: /}

          expect(ipset).to_not be_empty

          ipset = Hash[ipset.map{|x| x.strip.split(': ')}]
          ipset['entries'] = ipset['entries'].split(/\s+/)

          expect(ipset['entries']).to include(match(%r{3\.4\.5\.6}))
          expect(ipset['entries']).to include(match(%r{5\.6\.7\.8}))
        end
      end

      context 'UDP listen' do
        let(:manifest) {
          <<-EOM
            #{default_manifest}

            iptables::listen::udp { 'allow_udp_listen':
              trusted_nets => ['2.3.4.5/8', '3.4.5.6', '5.6.7.8/32'],
              dports       => 2345
            }
          EOM
        }

        it 'should work with no errors' do
          apply_manifest_on(host, manifest, :catch_failures => true)
        end

        it 'should be idempotent' do
          apply_manifest_on(host, manifest, :catch_changes => true)
        end

        it 'should have the "simp_tcp_allow_sshd" service in the "simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd')
        end

        it 'should have an appropriate ruleset configured' do
          rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=simp').output.strip.lines

          target_ruleset = rulesets.grep(%r("simp_udp_allow_udp_listen"))

          expect(target_ruleset.size).to eq(2)

          expect(target_ruleset).to include(match(%r{2\.0\.0\.0/8}))

          ruleset_ipset = target_ruleset.grep(/ipset=/).first.match('ipset="(.+?)"')[1]

          expect(ruleset_ipset).to_not be_empty

          ipset = on(host, "firewall-cmd --info-ipset=#{ruleset_ipset}").output

          ipset = ipset.lines.delete_if{|x| x !~ /: /}

          expect(ipset).to_not be_empty

          ipset = Hash[ipset.map{|x| x.strip.split(': ')}]
          ipset['entries'] = ipset['entries'].split(/\s+/)

          expect(ipset['entries']).to include(match(%r{3\.4\.5\.6}))
          expect(ipset['entries']).to include(match(%r{5\.6\.7\.8}))
        end
      end
    end
  end
end
