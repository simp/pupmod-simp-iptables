require 'spec_helper.rb'

# NOTE: This is well exercised by the different 'listen' defines, this is only
# for basic testing.
describe 'iptables::rule', type: :define do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

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
          it {
            is_expected.to create_notify("iptables::rule with firewalld (#{title})")
              .with_message(%r{cannot be used.+Called from})
              .with_loglevel('warning')
          }
          it { is_expected.not_to create_iptables_rule(title) }
        end
      end

      context 'when explicitly using firewalld' do
        let(:hieradata) { 'firewall__firewalld' }

        it {
          is_expected.to create_notify("iptables::rule with firewalld (#{title})")
            .with_message(%r{cannot be used.+Called from})
            .with_loglevel('warning')
        }
        it { is_expected.not_to create_iptables_rule(title) }

        # Multiple iptables::rule declarations must not collide on a
        # duplicate Notify declaration in firewalld mode
        context 'with multiple iptables::rule declarations' do
          let(:pre_condition) do
            <<~PP
              iptables::rule { 'second_rule': content => 'bar' }
              iptables::rule { 'third_rule': content => 'baz' }
            PP
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_notify("iptables::rule with firewalld (#{title})") }
          it { is_expected.to create_notify('iptables::rule with firewalld (second_rule)') }
          it { is_expected.to create_notify('iptables::rule with firewalld (third_rule)') }
        end
      end
    end
  end
end
