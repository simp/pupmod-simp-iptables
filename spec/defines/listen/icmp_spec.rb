require 'spec_helper.rb'

describe 'iptables::listen::icmp', :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          facts = os_facts.dup

          if facts[:os][:release][:major] == '6'
            facts[:simplib__firewalls] = [ 'iptables' ]
          else
            facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
          end

          facts
        end

        context 'with default firewall settings' do
          context 'with trusted_nets in IPv4 CIDR format' do
            let( :title  ){ 'allow_icmp_1234' }
            let( :params ){{
              :icmp_types   => '8',
              :trusted_nets => ['10.0.2.0/24']
            }}

            it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }

            if os_facts[:os][:release][:major] != '8'
              it { is_expected.to create_iptables_rule("icmp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
            end
          end

          context 'with trusted_nets in IPv6 CIDR format' do
            let( :title  ){ 'allow_icmp_1234' }
            let( :params ){{
              :icmp_types   => '8',
              :trusted_nets => ['fe80::/64'],
              :apply_to     => 'ipv6'
            }}

            it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }

            if os_facts[:os][:release][:major] != '8'
              it { is_expected.to create_iptables_rule("icmp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
            end
          end
        end

        context 'when explicitly using firewalld' do
          let( :hieradata) { 'firewall__firewalld' }
          let( :title  ){ 'allow_icmp_1234' }
          let( :params ){{
            :icmp_types   => '8',
            :trusted_nets => ['10.0.2.0/24']
          }}

          it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }

          if os_facts[:os][:release][:major] == '6'
            it { is_expected.to create_iptables_rule("icmp_#{title}") }
          else
            it { is_expected.to create_simp_firewalld__rule("icmp_#{title}") }
          end
        end
      end
    end
  end
end
