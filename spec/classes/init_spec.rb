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
          it { is_expected.to contain_package('iptables').with_ensure('latest') }
          it { is_expected.to contain_service('iptables').with_ensure('running') }
          it { is_expected.to contain_service('iptables-retry').with_enable(true) }
          it { is_expected.to create_class('iptables::base_rules').with_allow_ping(true) }
          it { is_expected.to create_class('iptables::prevent_localhost_spoofing') }
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
          it { is_expected.to create_file('/etc/init.d/iptables').with_ensure('file') }
          it { is_expected.to create_file('/etc/init.d/iptables-retry').with_ensure('file') }
          it { is_expected.to create_file('/etc/sysconfig/iptables').with_ensure('file') }
          it { is_expected.to contain_service('firewalld').with_ensure('stopped') }
        end

        context "iptables class with firewall disabled from hiera via 'use_iptables: false'" do
          let(:hieradata) { "iptables__disable" }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_disable(true) }

          # iptables rules are only applied if the iptables_optimize resource is not disabled
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(true) }
        end

        context 'creating iptables resources with iterators' do
          context 'iptables_ports_hash in hiera with defaults ' do
            let(:hieradata){ 'iptables__ports' }
            it { is_expected.to create_iptables__add_tcp_stateful_listen('port_80').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__add_udp_listen('port_53').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__add_tcp_stateful_listen('port_443').with({ :apply_to => 'ipv6'}) }
          end

        end

      end
    end
  end
end
