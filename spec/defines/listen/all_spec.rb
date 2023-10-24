require 'spec_helper.rb'

describe 'iptables::listen::all', :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          facts = os_facts.dup
          facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
          facts
        end

        context 'with default firewall settings' do
          context 'with trusted_nets in IPv4 CIDR format' do
            let( :title  ){ 'allow_all_1234' }
            let( :params ){{
              :trusted_nets => ['10.0.2.0/24']
            }}

            it { is_expected.to create_iptables__listen__all('allow_all_1234') }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("all_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end
          end

          context 'with trusted_nets in IPv6 CIDR format' do
            let( :title  ){ 'allow_all_1234' }
            let( :params ){{
              :trusted_nets => ['fe80::/64'],
              :apply_to    => 'ipv6'
            }}

            it { is_expected.to create_iptables__listen__all('allow_all_1234') }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("all_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end
          end
        end

        context 'when explicitly using firewalld' do
          let( :hieradata ) { 'firewall__firewalld' }
          let( :title  ){ 'allow_all_1234' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0/24']
          }}

          it { is_expected.to create_iptables__listen__all('allow_all_1234') }
          it { is_expected.to create_simp_firewalld__rule("all_#{title}") }

        end
      end
    end
  end
end
