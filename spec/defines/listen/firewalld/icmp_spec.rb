require 'spec_helper.rb'

describe "iptables::listen::icmp", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
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
            let( :title  ){ 'allow_icmp_1234' }
            let( :params ){{
              :icmp_types   => '8',
              :trusted_nets => ipv4_nets + ipv6_nets
            }}
            it { is_expected.to create_iptables__listen__icmp(title) }

            it {
              is_expected.to create_firewalld_rich_rule("11_simp_icmp_#{title}_ipv4_10_0_2_0_24").with(
                {
                  :ensure     => 'present',
                  :family     => 'ipv4',
                  :icmp_block => ['8'],
                  :source     => '10.0.2.0/24',
                  :action     => 'accept',
                  :zone       => 'simp'
                }
              )
            }

            it {
              is_expected.to create_firewalld_rich_rule("11_simp_icmp_#{title}_ipv6_ipset_simp_inet6_9nJdyQWwFic2bZPsGnwH_").with(
                {
                  :ensure     => 'present',
                  :family     => 'ipv6',
                  :icmp_block => ['8'],
                  :source     => {'ipset' => 'simp_inet6_9nJdyQWwFic2bZPsGnwH'},
                  :action     => 'accept',
                  :zone       => 'simp'
                }
              )
            }
          end
        end
      end
    end
  end
end
