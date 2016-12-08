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
          it { is_expected.to create_class('iptables').with_disable(true) }
          it { is_expected.to contain_package('iptables').with_ensure('latest') }
          it { is_expected.to contain_service('iptables').with_ensure('running') }
          it { is_expected.to contain_service('iptables-retry').with_enable(true) }
          it { is_expected.to create_class('iptables::base_rules').with_allow_ping(true) }
          it { is_expected.to create_class('iptables::prevent_localhost_spoofing') }
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(true) }
          it { is_expected.to create_file('/etc/init.d/iptables').with_ensure('file') }
          it { is_expected.to create_file('/etc/init.d/iptables-retry').with_ensure('file') }
          it { is_expected.to create_file('/etc/sysconfig/iptables').with_ensure('file') }
          it { is_expected.to contain_service('firewalld').with_ensure('stopped') }
        end

        context "iptables class with firewall enabled from hiera via 'simp_options::firewall: true'" do
          let(:hieradata) { "firewall__enable" }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_disable(false) }

          # iptables rules are only applied if the iptables_optimize resource is not disabled
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
        end
      end
    end
  end
end
