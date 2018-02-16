require 'spec_helper.rb'

describe 'iptables::ports', :type => :define do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:title) { 'iptables' }

      context 'a hash without a default section' do
        let(:params) {{
          'ports' => {
            '443' => {
              'apply_to' => 'ipv6'
            },
            '53' => {
              'proto' => 'udp'
            },
            '514' => {
              'proto' => ['udp','tcp']
            },
            '80' => nil,
          }
        }}
        it { is_expected.to compile.with_all_deps }
        # it { require 'pry';binding.pry }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_443_tcp').with(apply_to: 'ipv6') }
        it { is_expected.to create_iptables__listen__udp('port_53_udp').with(apply_to: 'auto') }
        it { is_expected.to create_iptables__listen__udp('port_514_udp').with(apply_to: 'auto') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_514_tcp').with(apply_to: 'auto') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_80_tcp') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_80_tcp').with(apply_to: 'auto') }
      end

      context 'containing a defaults section' do
        let(:params) {{
          'ports' => {
            'defaults' => {
              'apply_to' => 'ipv4',
              'proto'    => 'tcp'
            },
            '443' => {
              'apply_to' => 'ipv6'
            },
            '53'=> {
              'proto' => 'udp'
            },
            '514' => {
              'proto' => ['udp','tcp']
            },
            '80' => nil,
          }
        }}
        it { is_expected.to compile.with_all_deps }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_443_tcp').with(apply_to: 'ipv6') }
        it { is_expected.to create_iptables__listen__udp('port_53_udp').with(apply_to: 'ipv4') }
        it { is_expected.to create_iptables__listen__udp('port_514_udp').with(apply_to: 'ipv4') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_514_tcp').with(apply_to: 'ipv4') }
        it { is_expected.to create_iptables__listen__tcp_stateful('port_80_tcp').with(apply_to: 'ipv4') }
      end

      context 'a hash containing an invalid parameter' do
        let(:params) {{
          'ports' => {
            'defaults' => {
              'apply_to' => 'ipv4'
            },
            '53' => {
              'param' => 'udp'
            },
            '443' => {
              'apply_to' => 'ipv6'
            },
            '80' => nil,
          }
        }}
        it { is_expected.to raise_error(/param/) }
      end
    end
  end
end
