require 'spec_helper.rb'

describe "iptables::listen::udp", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        describe "with IPv4 trusted_nets" do
          let( :title  ){ 'allow_udp_range' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0'],
            :dports       => [1234,'9999:20000']
          }}
          it { is_expected.to create_iptables__listen__udp("allow_udp_range").with_dports(params[:dports]) }
        end

        describe "with IPv4 trusted_netsi in CIDR notation" do
          let( :title  ){ 'allow_udp_1234' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0/24'],
            :dports       => 1234
          }}
          it { is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234) }
        end

        describe "with IPv6 trusted_nets" do
          let( :title  ){ 'allow_udp_1234' }
          let( :params ){{
            :trusted_nets => ['fe80::'],
            :dports      => 1234,
            :apply_to    => 'ipv6'
          }}
          it { is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234) }
          it { is_expected.to create_iptables_rule('udp_allow_udp_1234') }
        end

        describe "with IPv6 trusted_nets in CIDR format" do
          let( :title  ){ 'allow_udp_1234' }
          let( :params ){{
            :trusted_nets => ['fe80::/64'],
            :dports      => 1234,
            :apply_to    => 'ipv6'
          }}
          it{
            is_expected.to create_iptables__listen__udp('allow_udp_1234').with_dports(1234)
          }
          it{
            is_expected.to create_iptables_rule('udp_allow_udp_1234')
          }
        end
      end
    end
  end
end
