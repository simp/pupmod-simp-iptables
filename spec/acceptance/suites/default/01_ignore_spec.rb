require 'spec_helper_acceptance'

test_name 'ignore interface'

hosts.each do |host|
  next unless host[:roles].include?('iptables')

  describe "ignore iptables rules on #{host}" do
    context 'apply rules and toggle iptables::ignore' do
      nic = fact_on(host, 'networking.primary').strip
      # Remove last character and add universal matcher to test regex
      nic_regex = "#{nic.chop}.*"

      let(:manifest) do
        <<-EOS
        include 'iptables'

        # Ironically, if iptables applies correctly, its default settings will
        # deny Vagrant access via SSH.  So, it is neccessary for beaker to also
        # define a rule that permit SSH access from the standard Vagrant subnets:
        iptables::listen::tcp_stateful { 'allow_sshd':
          trusted_nets => ['0.0.0.0/0'],
          dports       => 22,
        }
      EOS
      end

      let(:hieradata_nic_only) do
        <<-EOS
---
iptables::ignore: ['#{nic_regex}']
      EOS
      end
      let(:hieradata_nic_lo) do
        <<-EOS
---
iptables::ignore: ['#{nic_regex}','lo']
      EOS
      end

      it 'applies ignore => [] with no errors' do
        apply_manifest_on(host, manifest, catch_failures: true)
        on(host, 'iptables-save')
      end

      it 'applies rules without puppet' do
        on(host, "iptables -A INPUT -p tcp -i #{nic} --dport 6969 -j ACCEPT", acceptable_exit_codes: 0)
        on(host, 'iptables -A INPUT -p tcp -i lo --dport 6969 -j ACCEPT', acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep #{nic} | grep -w 6969", acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep lo | grep -w 6969", acceptable_exit_codes: 0)
      end

      it 'noes longer contain the rule after puppet apply' do
        apply_manifest_on(host, manifest, catch_failures: true)
        on(host, 'iptables-save')
        on(host, "iptables-save | grep ' -p tcp' | grep -w 6969", acceptable_exit_codes: 1)
      end

      it 'applies hieradata nic,lo' do
        set_hieradata_on(host, hieradata_nic_lo)
      end

      it 're-applies rules without puppet' do
        on(host, "iptables -A INPUT -p tcp -i #{nic} --dport 6969 -j ACCEPT", acceptable_exit_codes: 0)
        on(host, 'iptables -A INPUT -p tcp -i lo --dport 6969 -j ACCEPT', acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep #{nic} | grep -w 6969", acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep lo | grep -w 6969", acceptable_exit_codes: 0)
      end

      it "applies ignore => #{nic_regex},lo with no errors" do
        apply_manifest_on(host, manifest, catch_failures: true)
      end

      it "applies ignore => #{nic_regex},lo and be idempotent" do
        apply_manifest_on(host, manifest, catch_changes: true)
      end

      it "contains manually created rules on ignored interfaces: #{nic},lo" do
        on(host, "iptables-save | grep ' -p tcp' | grep #{nic} | grep -w 6969", acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep lo | grep -w 6969", acceptable_exit_codes: 0)
      end

      it 'applies hieradata nic only' do
        set_hieradata_on(host, hieradata_nic_only)
      end

      it "applies ignore => #{nic_regex} with no errors" do
        apply_manifest_on(host, manifest, catch_failures: true)
        on(host, 'iptables-save')
      end

      it "applies ignore => #{nic_regex} and be idempotent" do
        apply_manifest_on(host, manifest, catch_changes: true)
      end

      it "onlies contain manually created rules on ignored interface: #{nic}" do
        on(host, "iptables-save | grep ' -p tcp' | grep #{nic} | grep -w 6969", acceptable_exit_codes: 0)
        on(host, "iptables-save | grep ' -p tcp' | grep lo | grep -w 6969", acceptable_exit_codes: 1)
      end
    end
  end
end
