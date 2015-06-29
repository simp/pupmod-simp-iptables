describe "iptables::add_tcp_stateful_listen", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        context "with client_nets in CIDR format" do
          let( :title  ){ 'allow_tcp_1234' }
          let( :params ){{
            :client_nets => ['10.0.2.0/24'],
            :dports      => '1234'
          }}
          it { is_expected.to create_iptables__add_tcp_stateful_listen('allow_tcp_1234').with_dports('1234') }
        end
      end
    end
  end
end
