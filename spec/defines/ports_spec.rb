require 'spec_helper.rb'

describe "iptables::ports", :type => :define do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) do
        facts
      end
      let(:title) { 'iptables_test' }

      context 'a hash without a default section' do
        let(:params) {{
          'ports' => {
            '80' => nil,
            '53' => {
              'proto' => 'udp',
            },
            '443' => {
              'apply_to' => 'ipv6'
            },
            '88' => {
              'proto' => ['udp','tcp']
            },
            '1234' => {
              'proto' => 'tcp',
              'trusted_nets' => ['1.2.3.4']
            }
          }
        }}
        it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with(apply_to: 'auto') }
        it { is_expected.to create_iptables__listen__udp('port_53').with(apply_to: 'auto') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with(apply_to: 'ipv6') }
        it { is_expected.to create_iptables__listen__udp('port_88').with({ :apply_to => 'auto'}) }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_88').with({ :apply_to => 'auto'}) }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_1234').with({ :apply_to => 'auto', :trusted_nets => ['1.2.3.4']}) }
      end

      context 'containing a defaults section' do
        let(:params) {{
          'ports' => {
            'defaults' => {
              'apply_to' => 'ipv4',
              'proto'    => 'tcp'
            },
            '80'=> nil,
            '53'=> {
              'proto' => 'udp'
            },
            '443' => {
              'apply_to' => 'ipv6'
            }
          }
        }}
        it { is_expected.to create_iptables__listen__tcp_stateful('port_80').with(apply_to: 'ipv4') }
        it { is_expected.to create_iptables__listen__udp('port_53').with(apply_to: 'ipv4') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_443').with(apply_to: 'ipv6') }
      end

      context 'a hash containing an invalid parameter' do
        let(:params) {{
          'ports' => {
            'defaults' => {
              'apply_to' => 'ipv4'
            },
            '80' => nil,
            '53' => {
              'param' => 'udp'
            },
            '443' => {
              'apply_to' => 'ipv6'
            }
          }
        }}
        it { is_expected.to raise_error(/param/) }
      end
    end
  end
end
