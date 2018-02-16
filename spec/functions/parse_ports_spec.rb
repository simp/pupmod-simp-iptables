require 'spec_helper'

describe 'iptables::parse_ports' do

  inputs = {
    'a hash without a default section' => {
      '80'  => nil,
      '53'  => { 'proto' => 'udp' },
      '443' => { 'apply_to' => 'ipv6' },
      '514' => { 'proto' => ['udp','tcp'] }
    },
    'containing a defaults section' => {
      'defaults' => {
        'apply_to' => 'ipv4',
        'proto'    => 'tcp'
      },
      '443' => { 'apply_to' => 'ipv6' },
      '53'  => { 'proto' => 'udp' },
      '514' => { 'proto' => ['udp','tcp'] },
      '80'  => nil,
    },
    'a hash containing an invalid parameter' => {
      'defaults' => {
        'apply_to' => 'ipv4'
      },
      '53'  => { 'param' => 'udp' },
      '443' => { 'apply_to' => 'ipv6' },
      '80'  => nil,
    }
  }

  outputs = {
    'a hash without a default section' => {
      'port_80_tcp'  => { 'dports' => [80]  },
      'port_53_udp'  => { 'dports' => [53]  },
      'port_443_tcp' => { 'dports' => [443], 'apply_to' => 'ipv6'},
      'port_514_udp' => { 'dports' => [514] },
      'port_514_tcp' => { 'dports' => [514] },
    },
    'containing a defaults section' => {
      'port_443_tcp' => { 'dports' => [443], 'apply_to' => 'ipv6'},
      'port_53_udp'  => { 'dports' => [53],  'apply_to' => 'ipv4'},
      'port_514_udp' => { 'dports' => [514], 'apply_to' => 'ipv4'},
      'port_514_tcp' => { 'dports' => [514], 'apply_to' => 'ipv4'},
      'port_80_tcp'  => { 'dports' => [80],  'apply_to' => 'ipv4'},
    },
    'a hash containing an invalid parameter' => {
      'port_53_tcp'  => { 'dports' => [53],  'apply_to' => 'ipv4', 'param' => 'udp'},
      'port_443_tcp' => { 'dports' => [443], 'apply_to' => 'ipv6'},
      'port_80_tcp'  => { 'dports' => [80],  'apply_to' => 'ipv4'},
    },
  }

  # inputs.keys.each do |test_name|
  #   context test_name do
  #     it {
  #       is_expected.to run
  #         .with_params(inputs[test_name])
  #         .and_return(outputs[test_name])
  #       }
  #   end
  # end
end
