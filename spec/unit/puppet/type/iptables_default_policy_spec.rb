#!/usr/bin/env rspec

require 'spec_helper'

iptables_default_policy_type = Puppet::Type.type(:iptables_default_policy)

describe iptables_default_policy_type do
  before(:each) do
    @catalog = Puppet::Resource::Catalog.new
    Puppet::Type::Iptables_default_policy.any_instance.stubs(:catalog).returns(@catalog)
  end

  context ':name' do
    it 'should accept valid values' do
      valid_values = {
        'ipv4' => {
          'filter' => [
            'INPUT',
            'FORWARD',
            'OUTPUT'
          ]
        },
        'ipv6' => {
          'filter' => [
            'INPUT',
            'FORWARD',
            'OUTPUT'
          ]
        }
      }

      valid_values.each_pair do |proto, data|
        data.each do |tmp_table, chains|
          [tmp_table, tmp_table.upcase].each do |table|
            (chains + chains.map(&:downcase)).each do |chain|

              resource = iptables_default_policy_type.new(
                :name     => "#{table}:#{chain}",
                :apply_to => proto
              )

              expect(resource[:table].downcase).to eq(table.downcase)
              expect(resource[:chain].downcase).to eq(chain.downcase)
              expect(resource[:policy]).to eq('DROP')
            end
          end
        end
      end
    end

    it 'should not allow conflicting resources' do
      resource1 = iptables_default_policy_type.new( :name => 'filter:INPUT' )
      resource2 = iptables_default_policy_type.new( :name => 'filter:input' )
      resource3 = iptables_default_policy_type.new( :name => 'filter:output' )

      @catalog.add_resource(resource1)

      expect { @catalog.add_resource(resource2) }.to raise_error(/already declared/)

      @catalog.add_resource(resource3)
    end

    it 'should not accept invalid title patterns' do
      expect { iptables_default_policy_type.new(:name => 'foo') }.to raise_error(/No set of title patterns/)
      expect { iptables_default_policy_type.new(:name => '') }.to raise_error(/No set of title patterns/)
    end

    it 'should not accept invalid tables' do
      expect { iptables_default_policy_type.new(:name => 'foo:INPUT') }.to raise_error(/Invalid table 'foo'/)
      expect { iptables_default_policy_type.new(:name => ' :INPUT') }.to raise_error(/Invalid table ' '/)
      expect { iptables_default_policy_type.new(:name => ':INPUT') }.to raise_error(/Invalid table ''/)
    end

    it 'should not accept invalid chains' do
      expect { iptables_default_policy_type.new(:name => 'filter:BOB') }.to raise_error(/Invalid chain 'BOB'/)
      expect { iptables_default_policy_type.new(:name => 'filter: ') }.to raise_error(/Invalid chain ' '/)
      expect { iptables_default_policy_type.new(:name => 'filter:') }.to raise_error(/Invalid chain ''/)
    end
  end
end
