require 'spec_helper.rb'

describe "iptables::listen::icmp", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "with trusted_nets in IPv4 CIDR format" do
          let( :title  ){ 'allow_icmp_1234' }
          let( :params ){{
            :icmp_types   => '8',
            :trusted_nets => ['10.0.2.0/24']
          }}
          it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }
        end

        context "with trusted_nets in IPv6 CIDR format" do
          let( :title  ){ 'allow_icmp_1234' }
          let( :params ){{
            :icmp_types   => '8',
            :trusted_nets => ['fe80::/64'],
            :apply_to     => 'ipv6'
          }}
          it { is_expected.to create_iptables__listen__icmp('allow_icmp_1234') }
          it { is_expected.to create_iptables_rule('icmp_allow_icmp_1234') }
        end
      end
    end
  end
end
