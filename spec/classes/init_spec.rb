require 'spec_helper'

describe 'iptables' do

  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do
        context "iptables class without any parameters" do
          let(:params) {{ }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_disable(false) }
          it { is_expected.to create_iptables_rule('global') }
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
        end

        context "iptables class with firewall disabled from hiera via 'use_iptables: false'" do
          let(:hieradata) { "iptables__disable" }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_disable(true) }

          # iptables rules are only applied if the iptables_optimize resource is not disabled
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(true) }
        end
      end
    end
  end

  it 'implements rules correctly' do
    skip 'TODO: WRITE TESTS FOR IPTABLES RULES!'
  end
end
