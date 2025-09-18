require 'spec_helper'

if Puppet.version.to_f >= 4.5
  describe 'iptables_destport', type: :class do
    describe 'valid handling' do
      let(:pre_condition) do
        %(
          class #{class_name} (
            Iptables::DestPort $param
          ){ }

          class { '#{class_name}':
            param => #{param}
          }
        )
      end

      context 'with valid ranges' do
        [
          22,
          '65534:65535',
          [80, 443],
          ['1234:1236', 22, '59:300'],
        ].each do |param|
          let(:param) do
            if param.is_a?(String)
              param = "'#{param}'"
            end

            param
          end

          it "works with #{param}" do
            is_expected.to compile
          end
        end
      end

      context 'with invalid ranges' do
        [
          '22',
          '65534:65536',
          [80, 65_537],
          ['1234:1236', 555_555, '59:300'],
        ].each do |param|
          let(:param) do
            if param.is_a?(String)
              param = "'#{param}'"
            end

            param
          end

          it "fails on #{param}" do
            is_expected.to compile.and_raise_error(%r{parameter 'param' .* expects})
          end
        end
      end
    end
  end
end
