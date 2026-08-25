require 'spec_helper.rb'

describe 'iptables::listen::icmp', type: :define do
  context 'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) { os_facts }

        context 'with default firewall settings' do
          context 'with trusted_nets in IPv4 CIDR format' do
            let(:title) { 'allow_icmp_1234' }
            let(:params) do
              {
                icmp_types: '8',
                trusted_nets: ['10.0.2.0/24'],
              }
            end

            it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("icmp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
            end
          end

          context 'with trusted_nets in IPv6 CIDR format' do
            let(:title) { 'allow_icmp_1234' }
            let(:params) do
              {
                icmp_types: '8',
                trusted_nets: ['fe80::/64'],
                apply_to: 'ipv6',
              }
            end

            it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("icmp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
            end
          end
        end

        context 'when explicitly using firewalld' do
          let(:hieradata) { 'firewall__firewalld' }
          let(:title) { 'allow_icmp_1234' }
          let(:params) do
            {
              icmp_types: '8',
              trusted_nets: ['10.0.2.0/24'],
            }
          end

          it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }
          it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
        end

        context 'with backend => iptables' do
          let(:hieradata) { 'firewall__iptables' }
          let(:title) { 'allow_icmp_1234' }
          let(:params) do
            {
              icmp_types: '8',
              trusted_nets: ['10.0.2.0/24'],
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables_rule("icmp_#{title}") }
          it { is_expected.not_to create_simp_firewalld__rule("icmp_#{title}") }
        end

        context 'with deprecated use_firewalld => false' do
          let(:hieradata) { 'firewall__use_firewalld_false' }
          let(:title) { 'allow_icmp_1234' }
          let(:params) do
            {
              icmp_types: '8',
              trusted_nets: ['10.0.2.0/24'],
            }
          end

          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables_rule("icmp_#{title}") }
          it { is_expected.not_to create_simp_firewalld__rule("icmp_#{title}") }
        end
      end
    end
  end
end
