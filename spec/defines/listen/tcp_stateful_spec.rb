require 'spec_helper.rb'

describe "iptables::listen::tcp_stateful", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "with trusted_nets in IPv4 CIDR format" do
          let( :title  ){ 'allow_tcp_1234' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0/24'],
            :dports      => [1234, '234:567']
          }}
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_tcp_1234').with_dports(params[:dports]) }
        end

        context "with trusted_nets in IPv6 CIDR format" do
          let( :title  ){ 'allow_tcp_1234' }
          let( :params ){{
            :trusted_nets => ['fe80::/64'],
            :dports      => 1234,
            :apply_to    => 'ipv6'
          }}
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_tcp_1234').with_dports(1234) }
          it { is_expected.to create_iptables_rule('tcp_allow_tcp_1234') }
        end

        # This tests for the bug reported in SIMP-263
        context "with more than 10 ports" do
          let( :title  ){ 'allow_tcp_more_than_10_ports' }
          let( :params ){{
            :trusted_nets => ['10.0.2.0/24'],
            :dports      => (101..111).to_a
          }}
          # does the catalog accept it?
          it { is_expected.to create_iptables__listen__tcp_stateful('allow_tcp_more_than_10_ports').with_dports((101..111).to_a)
          }

          # does it create the correct rule?
          it {
            is_expected.to create_iptables_rule('tcp_allow_tcp_more_than_10_ports').with_content(/ --dports 101,102,103,104,105,106,107,108,109,110,111 -j ACCEPT/) }
        end
      end
    end
  end
end
