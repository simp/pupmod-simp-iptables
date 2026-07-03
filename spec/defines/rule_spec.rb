require 'spec_helper.rb'

# NOTE: This is well exercised by the different 'listen' defines, this is only
# for basic testing.
describe 'iptables::rule', type: :define do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        facts = os_facts.dup
        facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
        facts
      end

      let(:title) { 'iptables_firewalld' }

      let(:params) do
        {
          content: 'foo',
        }
      end

      context 'by default' do
        if os_facts[:os][:release][:major].to_i < 8
          it { is_expected.to create_iptables_rule(title) }
        else
          # In firewalld mode iptables::rule is a warned no-op
          it { is_expected.to compile.with_all_deps }
          it { is_expected.not_to create_iptables_rule(title) }
        end
      end

      context 'when explicitly using firewalld' do
        let(:hieradata) { 'firewall__firewalld' }

        # In firewalld mode iptables::rule is a warned no-op
        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to create_iptables_rule(title) }
      end
    end
  end
end
