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
        iptables::listen::tcp_stateful { 'allow_sshd_0.0.0.0':
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
        it 'should have "99_simp" as the default zone' do
          default_zone = on(host, 'firewall-cmd --get-default-zone').output.strip
          expect(default_zone).to eq('99_simp')
        end

        it 'should have the "simp_tcp_allow_sshd_0_0_0_0" service in the "99_simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd_0_0_0_0')
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

        it 'should have the "simp_tcp_allow_sshd_0_0_0_0" service in the "99_simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd_0_0_0_0')
        end

        it 'should have an appropriate ruleset configured' do
          rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=99_simp').output.strip.lines

          target_ruleset = rulesets.grep(%r("simp_tcp_allow_tcp_listen"))

          expect(target_ruleset.size).to eq(2)

          hash_ip_ipset = 'simp-gEi0qMBFhbv6eiaWYmkwap62GS'
          hash_net_ipset = 'simp-j07oVIg3S8ccSfyQGfBvCdqsCv'

          expect(target_ruleset).to include(match(%r{ipset="#{hash_ip_ipset}"}))
          expect(target_ruleset).to include(match(%r{ipset="#{hash_net_ipset}"}))

          hash_ip_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_ip_ipset}").output

          hash_ip_ipset_contents = hash_ip_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_ip_ipset_contents).to_not be_empty

          hash_ip_ipset_contents = Hash[hash_ip_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_ip_ipset_contents['entries'] = hash_ip_ipset_contents['entries'].split(/\s+/)

          expect(hash_ip_ipset_contents['entries']).to include(match(%r{3\.4\.5\.6}))
          expect(hash_ip_ipset_contents['entries']).to include(match(%r{5\.6\.7\.8}))

          hash_net_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_net_ipset}").output

          hash_net_ipset_contents = hash_net_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_net_ipset_contents).to_not be_empty

          hash_net_ipset_contents = Hash[hash_net_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_net_ipset_contents['entries'] = hash_net_ipset_contents['entries'].split(/\s+/)

          expect(hash_net_ipset_contents['entries']).to include(match(%r{1\.2\.3\.0/24}))
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

        it 'should have the "simp_tcp_allow_sshd_0_0_0_0" service in the "99_simp" zone' do
          simp_services = on(host, 'firewall-cmd --list-services --zone=99_simp').output.strip.split(/\s+/)
          expect(simp_services).to include('simp_tcp_allow_sshd_0_0_0_0')
        end

        it 'should have an appropriate ruleset configured' do
          rulesets = on(host, 'firewall-cmd --list-rich-rules --zone=99_simp').output.strip.lines

          target_ruleset = rulesets.grep(%r("simp_udp_allow_udp_listen"))

          expect(target_ruleset.size).to eq(2)

          hash_ip_ipset = 'simp-BahW5mYEj6huIkJdFkE4gS68zH'
          hash_net_ipset = 'simp-ijfIJaYoC8b8MC3CPSwRFKY6h9'

          expect(target_ruleset).to include(match(%r{ipset="#{hash_ip_ipset}"}))
          expect(target_ruleset).to include(match(%r{ipset="#{hash_net_ipset}"}))

          hash_ip_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_ip_ipset}").output

          hash_ip_ipset_contents = hash_ip_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_ip_ipset_contents).to_not be_empty

          hash_ip_ipset_contents = Hash[hash_ip_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_ip_ipset_contents['entries'] = hash_ip_ipset_contents['entries'].split(/\s+/)

          expect(hash_ip_ipset_contents['entries']).to include(match(%r{3\.4\.5\.6}))
          expect(hash_ip_ipset_contents['entries']).to include(match(%r{5\.6\.7\.8}))

          hash_net_ipset_contents = on(host, "firewall-cmd --info-ipset=#{hash_net_ipset}").output

          hash_net_ipset_contents = hash_net_ipset_contents.lines.delete_if{|x| x !~ /: /}

          expect(hash_net_ipset_contents).to_not be_empty

          hash_net_ipset_contents = Hash[hash_net_ipset_contents.map{|x| x.strip.split(': ')}]
          hash_net_ipset_contents['entries'] = hash_net_ipset_contents['entries'].split(/\s+/)

          expect(hash_net_ipset_contents['entries']).to include(match(%r{2\.0\.0\.0/8}))
        end
      end
    end
  end
end
