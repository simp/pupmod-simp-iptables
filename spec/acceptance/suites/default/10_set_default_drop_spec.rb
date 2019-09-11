require 'spec_helper_acceptance'

test_name 'iptables::rules::default_drop'

hosts.each do |host|
  next unless host[:roles].include?('iptables')

  describe 'iptables::rules::default_drop' do
    let(:manifest) { 'include iptables' }

    let(:hieradata){{
      # We're not setting 'output' rules to drop deliberately.
      'iptables::rules::default_drop::filter_input'   => true,
      'iptables::rules::default_drop::filter_forward' => true,
      'iptables::rules::default_drop::filter_output'  => false,

      # Allow beaker back in.
      'iptables::ports' => {
        22 => {
          'trusted_nets' => ['0.0.0.0/0']
        }
      }
    }}

    it 'should work without errors' do
      set_hieradata_on(host, hieradata)
      apply_manifest_on(host, manifest, :catch_failures => true)
    end

    it 'should have a default drop for triggered built-in ipv4 chains' do
      iptables_info = on(host, 'iptables-save -t filter').output.lines.map(&:strip)

      iptables_info = Hash[iptables_info.grep(/^:/).map{ |x|
        chain, policy = x.split(/\s+/)

        chain.delete!(':')
        [chain, policy]
      }]

      expect(iptables_info['INPUT']).to eq('DROP')
      expect(iptables_info['FORWARD']).to eq('DROP')
      expect(iptables_info['OUTPUT']).to eq('ACCEPT')
    end

    it 'should have a default drop for triggered built-in ipv6 chains' do
      iptables_info = on(host, 'ip6tables-save -t filter').output.lines.map(&:strip)

      iptables_info = Hash[iptables_info.grep(/^:/).map{ |x|
        chain, policy = x.split(/\s+/)

        chain.delete!(':')
        [chain, policy]
      }]

      expect(iptables_info['INPUT']).to eq('DROP')
      expect(iptables_info['FORWARD']).to eq('DROP')
      expect(iptables_info['OUTPUT']).to eq('ACCEPT')
    end
  end
end
