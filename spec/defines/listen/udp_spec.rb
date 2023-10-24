require 'spec_helper.rb'

describe 'iptables::listen::udp', :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          facts = os_facts.dup
          facts[:simplib__firewalls] = [ 'firewalld', 'iptables' ]
          facts
        end

        context 'with default firewall settings' do
          describe 'with IPv4 trusted_nets' do
            let( :title  ){ 'allow_udp_range' }
            let( :params ){{
              :trusted_nets => ['10.0.2.0'],
              :dports       => [1234,'9999:20000']
            }}

            it { is_expected.to create_iptables__listen__udp('allow_udp_range').with_dports(params[:dports]) }

            if os_facts[:os][:release][:major].to_i < 8
              it do
                expected = "-m state --state NEW -p udp -s 10.0.2.0 -m multiport --dports 1234,9999:20000 -j ACCEPT\n"
                is_expected.to create_iptables_rule("udp_#{title}").with_content(expected)
              end
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end

          end

          describe 'with IPv4 trusted_nets in CIDR notation' do
            let( :title  ){ 'allow_udp_1234' }
            let( :params ){{
              :trusted_nets => ['10.0.2.0/24'],
              :dports       => 1234
            }}

            it { is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234) }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("udp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end
          end

          describe 'with IPv6 trusted_nets' do
            let( :title  ){ 'allow_udp_1234' }
            let( :params ){{
              :trusted_nets => ['fe80::'],
              :dports      => 1234,
              :apply_to    => 'ipv6'
            }}

            it { is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234) }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("udp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end
          end

          describe 'with IPv6 trusted_nets in CIDR format' do
            let( :title  ){ 'allow_udp_1234' }
            let( :params ){{
              :trusted_nets => ['fe80::/64'],
              :dports      => 1234,
              :apply_to    => 'ipv6'
            }}

            it { is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234) }

            if os_facts[:os][:release][:major].to_i < 8
              it { is_expected.to create_iptables_rule("udp_#{title}") }
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end
          end

          describe 'with more than 15 individual ports' do
            let( :title  ){ 'allow_udp_more_than_15_ports' }
            let( :params ){{
              :trusted_nets => ['10.0.2.0/24'],
              :dports      => (101..121).to_a
            }}

            it { is_expected.to create_iptables__listen__udp('allow_udp_more_than_15_ports').with_dports((101..121).to_a) }

            if os_facts[:os][:release][:major].to_i < 8
              it do
                expected = <<-EOM
-m state --state NEW -p udp -s 10.0.2.0/24 -m multiport --dports 101,102,103,104,105,106,107,108,109,110,111,112,113,114,115 -j ACCEPT
-m state --state NEW -p udp -s 10.0.2.0/24 -m multiport --dports 116,117,118,119,120,121 -j ACCEPT
                EOM
                is_expected.to create_iptables_rule("udp_#{title}").with_content(expected)
              end
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end
          end

          describe 'single port ranges' do
            let( :title  ){ 'allow_port_range' }
            let( :params ){{
              :trusted_nets => ['10.0.2.0/24'],
              :dports      => '150:300'
            }}

            it { is_expected.to create_iptables__listen__udp('allow_port_range').with_dports('150:300') }

            if os_facts[:os][:release][:major].to_i < 8
              it do
                expected = <<-EOM
-m state --state NEW -p udp -s 10.0.2.0/24 -m multiport --dports 150:300 -j ACCEPT
                EOM
                is_expected.to create_iptables_rule("udp_#{title}").with_content(expected)
              end
            else
              it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
            end
          end
        end

        context 'when explicitly using firewalld' do
          let( :hieradata ) { 'firewall__firewalld' }
          let( :title  ){ 'allow_udp_range' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0'],
            :dports       => [1234,'9999:20000']
          }}

          it { is_expected.to create_iptables__listen__udp('allow_udp_range').with_dports(params[:dports]) }
          it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
        end
      end
    end
  end
end
