require 'spec_helper'

if Puppet.version.to_f >= 4.5
  describe 'iptables_portrange', type: :class do
    describe 'valid handling' do
      let(:pre_condition) do
        %(
          class #{class_name} (
            Iptables::PortRange $param
          ){ }

          class { '#{class_name}':
            param => '#{param}'
          }
        )
      end

      context 'with valid ranges' do
        ['0:20', '80:81', '1024:2048', '65534:65535'].each do |param|
          let(:param) { param }

          it "works with #{param}" do
            is_expected.to compile
          end
        end
      end

      context 'with invalid ranges' do
        [-1, '0:65536', '2048:123456', 22, true].each do |param|
          let(:param) { param }

          it "fails on #{param}" do
            is_expected.to compile.and_raise_error(%r{parameter 'param' expects})
          end
        end
      end
    end
  end
end
