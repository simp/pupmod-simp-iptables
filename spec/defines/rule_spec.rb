require 'spec_helper.rb'

# NOTE: This is well exercised by the different 'listen' defines, this is only
# for basic testing.
describe "iptables::rule", :type => :define do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end

      let(:title) { 'iptables_firewalld' }

      let(:params){{
        :content => 'foo'
      }}

      context 'by default' do
        it { is_expected.to create_iptables_rule(title) }
      end

      context 'when using firewalld' do
        let(:hieradata) { 'firewall__firewalld' }

        it { is_expected.to create_notify('iptables::rule with firewalld').with(
            {
              :message  => /cannot be used.+Called from/,
              :loglevel => 'warning'
            }
          )
        }
      end
    end
  end
end
