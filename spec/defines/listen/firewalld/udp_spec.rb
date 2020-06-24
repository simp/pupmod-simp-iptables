require 'spec_helper.rb'

describe "iptables::listen::udp", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, os_facts|
      context "on #{os}" do
        let(:facts) do
          os_facts
        end

        let(:ipv4_nets) {
          [
            '10.0.2.0/24',
            '10.0.2.33/32',
            '1.2.3.4/32',
            '2.3.4.0/24',
            '3.0.0.0/8'
          ]
        }

        let(:ipv6_nets) {
          [
            'fe80::/64',
            '2001:cdba:0000:0000:0000:0000:3257:9652/128',
            '2001:cdba:0000:0000:0000:0000:3257:9652/16'
          ]
        }

        context 'firewalld mode' do
          let(:hieradata) { 'firewall__firewalld' }

          context "with trusted_nets in CIDR format" do
            let( :title  ){ 'allow_udp_range' }
            let( :params ){{
              :trusted_nets => ipv4_nets + ipv6_nets,
              :dports      => [1234, '234:567']
            }}

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_simp_firewalld__rule("udp_#{title}") }
          end
        end
      end
    end
  end
end
