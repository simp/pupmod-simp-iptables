describe "iptables::add_udp_listen", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "with IPv4 client_nets" do
          let( :title  ){ 'allow_udp_1234' }
          let( :params ){{
            :client_nets => ['10.0.2.0/24'],
            :dports      => '1234'
          }}
          it { is_expected.to create_iptables__add_udp_listen('allow_udp_1234').with_dports('1234') }
        end

        context "with IPv6 client_nets" do
          let( :title  ){ 'allow_udp_1234' }
          let( :params ){{
            :client_nets => ['fe80::'],
            :dports      => '1234',
            :apply_to    => 'ipv6'
          }}
          it { is_expected.to create_iptables__add_udp_listen('allow_udp_1234').with_dports('1234') }
          it { is_expected.to create_iptables_rule('udp_allow_udp_1234') }
        end
      end
    end
  end
end
