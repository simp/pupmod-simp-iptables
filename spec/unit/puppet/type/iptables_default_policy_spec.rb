#!/usr/bin/env rspec

require 'spec_helper'

describe Puppet::Type.type(:iptables_default_policy) do
  let(:catalog) { Puppet::Resource::Catalog.new }

  before(:each) do
    # rubocop:disable RSpec/AnyInstance
    allow_any_instance_of(Puppet::Type::Iptables_default_policy).to receive(:catalog).and_return(catalog)
    # rubocop:enable RSpec/AnyInstance
  end

  context ':name' do
    it 'accepts valid values' do
      valid_values = {
        'ipv4' => {
          'filter' => [
            'INPUT',
            'FORWARD',
            'OUTPUT',
          ],
        },
        'ipv6' => {
          'filter' => [
            'INPUT',
            'FORWARD',
            'OUTPUT',
          ],
        },
      }

      valid_values.each_pair do |proto, data|
        data.each do |tmp_table, chains|
          [tmp_table, tmp_table.upcase].each do |table|
            (chains + chains.map(&:downcase)).each do |chain|
              resource = described_class.new(
                name: "#{table}:#{chain}",
                apply_to: proto,
              )

              expect(resource[:table].downcase).to eq(table.downcase)
              expect(resource[:chain].downcase).to eq(chain.downcase)
              expect(resource[:policy]).to eq('DROP')
            end
          end
        end
      end
    end

    it 'does not allow conflicting resources' do
      resource1 = described_class.new(name: 'filter:INPUT')
      resource2 = described_class.new(name: 'filter:input')
      resource3 = described_class.new(name: 'filter:output')

      catalog.add_resource(resource1)

      expect { catalog.add_resource(resource2) }.to raise_error(%r{already declared})

      catalog.add_resource(resource3)
    end

    it 'does not accept invalid title patterns' do
      expect { described_class.new(name: 'foo') }.to raise_error(%r{No set of title patterns})
      expect { described_class.new(name: '') }.to raise_error(%r{No set of title patterns})
    end

    it 'does not accept invalid tables' do
      expect { described_class.new(name: 'foo:INPUT') }.to raise_error(%r{Invalid table 'foo'})
      expect { described_class.new(name: ' :INPUT') }.to raise_error(%r{Invalid table ' '})
      expect { described_class.new(name: ':INPUT') }.to raise_error(%r{Invalid table ''})
    end

    it 'does not accept invalid chains' do
      expect { described_class.new(name: 'filter:BOB') }.to raise_error(%r{Invalid chain 'BOB'})
      expect { described_class.new(name: 'filter: ') }.to raise_error(%r{Invalid chain ' '})
      expect { described_class.new(name: 'filter:') }.to raise_error(%r{Invalid chain ''})
    end
  end
end
