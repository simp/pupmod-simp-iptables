require 'spec_helper'

describe 'iptables::parse_ports' do

  tests = {
    'a port with details' => {
      'params' => {
        80 => {
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        }
      },
      'returns' => {
        'port_80_tcp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
      }
    },
    'a port with a specified proto' => {
      'params' => {
        80 => {
          'proto'        => 'udp',
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        }
      },
      'returns' => {
        'port_80_udp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
      }
    },
    'a port with two specified protos' => {
      'params' => {
        80 => {
          'proto'        => ['tcp','udp'],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        }
      },
      'returns' => {
        'port_80_tcp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
        'port_80_udp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
      }
    },
    'a port with nothing else' => {
      'params' => {
        80 => nil
      },
      'returns' => {
        'port_80_tcp' => {
          'dports' => [80],
        }
      }
    },
    'a few ports with a defaults section and a specified proto' => {
      'params' => {
        'defaults' => { 'apply_to' => 'auto' },
        80 => {
          'proto'        => 'udp',
          'trusted_nets' => ['192.168.1.0/24']
        }
      },
      'returns' => {
        'port_80_udp' => {
          'dports'       => [80],
          'apply_to'     => 'auto',
          'trusted_nets' => ['192.168.1.0/24']
        },
      }
    },
    'a few ports with a defaults section two specified protos' => {
      'params' => {
        'defaults' => { 'apply_to' => 'auto' },
        80 => {
          'proto'        => ['tcp','udp'],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        }
      },
      'returns' => {
        'port_80_tcp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
        'port_80_udp' => {
          'dports'       => [80],
          'apply_to'     => 'ipv4',
          'trusted_nets' => ['192.168.1.0/24']
        },
      }
    },
    'a few ports with a defaults section nothing else' => {
      'params' => {
        'defaults' => { 'apply_to' => 'auto' },
        80 => nil
      },
      'returns' => {
        'port_80_tcp' => {
          'dports'   => [80],
          'apply_to' => 'auto',
        },

      }
    },
  }

  tests.keys.each do |test_name|
    context test_name do
      it {
        is_expected.to run
          .with_params(tests[test_name]['params'])
          .and_return(tests[test_name]['returns'])
        }
    end
  end
end
