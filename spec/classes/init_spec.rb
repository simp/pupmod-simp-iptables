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
          it { is_expected.to create_class('iptables').with_enable(true) }
          it { is_expected.to contain_package('iptables').with_ensure('latest') }
          it { is_expected.to contain_service('iptables').with_ensure('running') }
          it { is_expected.to contain_service('iptables-retry').with_enable(true) }
          it { is_expected.to create_class('iptables::rules::base').with_allow_ping(true) }
          it { is_expected.to create_class('iptables::rules::prevent_localhost_spoofing') }
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
          it { is_expected.to create_file('/etc/init.d/iptables').with_ensure('file') }
          it { is_expected.to create_file('/etc/init.d/iptables-retry').with_ensure('file') }
          it { is_expected.to create_file('/etc/sysconfig/iptables') }
          it { is_expected.to contain_service('firewalld').with_ensure('stopped') }
        end

        context "iptables class with firewall enabled from hiera via 'simp_options::firewall: true'" do
          let(:hieradata) { "firewall__enable" }
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_enable(true) }

          # iptables rules are only applied if the iptables_optimize resource is not disabled
          it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
        end

        context "iptables::rules::base" do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables::rules::base') }
          it { is_expected.to create_iptables_rule('global').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_lo').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_v4_echo_request').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_all').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('drop_broadcast').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_v6_broadcast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('drop_v4_multicast').with_apply_to('ipv4')}
          it { is_expected.to create_iptables_rule('drop_v6_multicast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('established_related').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('log_all').with_apply_to('all') }
        end

        context "default spoofing prevention" do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables_rule('prevent_ipv6_localhost_spoofing').with_apply_to('ipv6') }
        end

        context 'iptables_ports_hash in hiera' do
          context 'defaults ' do
            let(:hieradata){ 'iptables__ports' }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__listen__udp('port_53').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with({ :apply_to => 'ipv6'}) }
          end
          context 'a hash without a default section' do
            let(:hieradata){ 'iptables__ports_no_default' }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with({ :apply_to => 'auto'}) }
            it { is_expected.to create_iptables__listen__udp('port_53').with({ :apply_to => 'auto'}) }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with({ :apply_to => 'ipv6'}) }
          end
          context 'a hash containing an invalid parameter' do
            let(:hieradata){ 'iptables__ports_bad_param' }
            it { is_expected.to raise_error(/param/) }
          end
        end

      end
    end
  end
end
