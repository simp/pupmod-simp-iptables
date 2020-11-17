require 'spec_helper.rb'

# NOTE: This is well exercised by the different 'listen' defines, this is only
# for basic testing.
describe 'iptables::rule', :type => :define do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        facts = os_facts.dup

        if facts[:os][:release][:major] == '6'
          facts[:simplib__firewalls] = [ 'iptables' ]
        else
          facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
        end

        facts
      end

      let(:title) { 'iptables_firewalld' }

      let(:params){{
        :content => 'foo'
      }}

      context 'by default' do
        if os_facts[:os][:release][:major] != '8'
          it { is_expected.to create_iptables_rule(title) }
        else
          it { is_expected.to create_notify('iptables::rule with firewalld')
            .with_message(/cannot be used.+Called from/)
            .with_loglevel('warning')
          }
        end
      end

      context 'when explicitly using firewalld' do
        let(:hieradata) { 'firewall__firewalld' }

        if os_facts[:os][:release][:major] == '6'
          it { is_expected.to create_iptables_rule(title) }
        else
          it { is_expected.to create_notify('iptables::rule with firewalld')
            .with_message(/cannot be used.+Called from/)
            .with_loglevel('warning')
          }
        end
      end
    end
  end
end
