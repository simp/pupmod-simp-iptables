require 'spec_helper'

describe 'iptables' do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      let(:facts) do
        # many of the tests assume the simplib__firewalls fact does not exist
        facts = os_facts.dup
        facts[:simplib__firewalls] = nil
        facts
      end

      context "on #{os}" do
        context "iptables class without any parameters" do
          let(:facts) do
            facts = os_facts.dup
            facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
            facts
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_enable(true) }

          if os_facts[:os][:release][:major] < '8'
            if os_facts[:os][:name] == 'Amazon'
              it { is_expected.to contain_package('iptables-services').with_ensure('present') }
            else
              it { is_expected.to contain_package('iptables').with_ensure('present') }
            end

            it { is_expected.to contain_service('iptables').with_ensure('running') }
            it { is_expected.to contain_service('iptables-retry').with_enable(true) }
            it { is_expected.to create_class('iptables::rules::base').with_allow_ping(true) }
            it { is_expected.to create_class('iptables::rules::prevent_localhost_spoofing') }
            it { is_expected.to create_iptables_optimize('/etc/sysconfig/iptables').with_disable(false) }
            it { is_expected.to create_file('/etc/init.d/iptables').with_ensure('file') }
            it { is_expected.to create_file('/etc/init.d/iptables-retry').with_ensure('file') }
            it { is_expected.to create_file('/etc/sysconfig/iptables') }
            it { is_expected.to contain_service('firewalld').with_ensure('stopped') }
            it { is_expected.to_not create_class('simp_firewalld') }
          else
            it { is_expected.to create_class('simp_firewalld') }
            it { is_expected.to_not create_iptables__ports('firewalld') }
            it { is_expected.not_to contain_package('iptables') }
            it { is_expected.not_to contain_package('iptables-ipv6') }
            it { is_expected.to contain_package('iptables-services').with_ensure('present') }
            it { is_expected.to_not create_class('iptables::service') }
            it { is_expected.to_not create_class('iptables::rules::default_drop') }
            it { is_expected.to_not create_file('/etc/sysconfig/iptables') }
            it { is_expected.to_not create_iptables_optimize('/etc/sysconfig/iptables') }
          end
        end

        context 'iptables class with use_firewalld=true' do
          let(:facts) do
            facts = os_facts.dup
            facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
            facts
          end

          let(:params) {{ :use_firewalld => true }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_enable(true) }

          it { is_expected.to create_class('simp_firewalld') }
          it { is_expected.to create_class('iptables::install') }
          it { is_expected.to_not create_class('iptables::service') }
        end

        context "iptables class with firewall enabled from hiera via 'simp_options::firewall: true'" do
          let(:hieradata) { "firewall__enable" }

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables').with_enable(true) }
        end

        context "iptables class with 'firewalld' enabled" do
          let(:facts){
            os_facts.merge({
              :simplib__firewalls => ['iptables', 'firewalld']
            })
          }

          let(:params){{
            enable: 'firewalld'
          }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('simp_firewalld') }
        end

        context "iptables::rules::base" do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables::rules::base') }
          it { is_expected.to create_iptables_rule('global').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_lo_input').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_lo_output').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_v4_echo_request').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_all').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('drop_broadcast').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_v6_broadcast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('drop_v4_multicast').with_apply_to('ipv4')}
          it { is_expected.to create_iptables_rule('drop_v6_multicast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('established_related').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('log_all').with_apply_to('all') }
        end

        context 'default spoofing prevention when not using firewalld' do
          let (:facts) { os_facts.merge( ipv6_enabled: true ) }
          let(:params) {{ :use_firewalld => false }}

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables_rule('prevent_ipv6_localhost_spoofing').with_apply_to('ipv6') }
        end

        context 'with a provided iptables::ports hash' do
          context 'containing a defaults section' do
            let(:hieradata){ 'iptables__ports_default' }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__listen__udp('port_53').with({ :apply_to => 'ipv4'}) }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with({ :apply_to => 'ipv6'}) }
          end
          context 'a hash without a default section' do
            let(:hieradata){ 'iptables__ports_no_default' }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with({ :apply_to => 'auto'}) }
            it { is_expected.to create_iptables__listen__udp('port_53').with({ :apply_to => 'auto'}) }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with({ :apply_to => 'ipv6'}) }
            it { is_expected.to create_iptables__listen__udp('port_88').with({ :apply_to => 'auto'}) }
            it { is_expected.to create_iptables__listen__tcp_stateful('port_88').with({ :apply_to => 'auto'}) }
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
