require 'spec_helper'

describe 'iptables::rules::default_drop' do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        os_facts
      end

      before(:each) do
        # Mask 'assert_private' for testing
        Puppet::Parser::Functions.newfunction(:assert_private, :type => :rvalue) { |args| }
      end

      context "on #{os}" do
        context 'by default' do
          it { is_expected.to compile.with_all_deps }
        end

        context 'enabling filter_input' do
          let(:params) {{ :filter_input => true }}
          it { is_expected.to create_iptables_default_policy('filter:INPUT').with_policy('DROP') }
        end

        context 'disabling filter_input' do
          let(:params) {{ :filter_input => false }}
          it { is_expected.to create_iptables_default_policy('filter:INPUT').with_policy('ACCEPT') }
        end

        context 'enabling filter_forward' do
          let(:params) {{ :filter_forward => true }}
          it { is_expected.to create_iptables_default_policy('filter:FORWARD').with_policy('DROP') }
        end

        context 'disabling filter_forward' do
          let(:params) {{ :filter_forward => false }}
          it { is_expected.to create_iptables_default_policy('filter:FORWARD').with_policy('ACCEPT') }
        end

        context 'enabling filter_output' do
          let(:params) {{ :filter_output => true }}
          it { is_expected.to create_iptables_default_policy('filter:OUTPUT').with_policy('DROP') }
        end

        context 'disabling filter_output' do
          let(:params) {{ :filter_output => false }}
          it { is_expected.to create_iptables_default_policy('filter:OUTPUT').with_policy('ACCEPT') }
        end
      end
    end
  end
end
