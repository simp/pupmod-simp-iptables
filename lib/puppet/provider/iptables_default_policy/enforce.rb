Puppet::Type.type(:iptables_default_policy).provide(:enforce) do
  desc 'Provider for manging the default iptables policies'

  commands iptables: 'iptables'
  commands iptables_save: 'iptables-save'

  optional_commands ip6tables: 'ip6tables'
  optional_commands ip6tables_save: 'ip6tables-save'

  mk_resource_methods

  attr_reader :needs_sync

  def self.instances
    gather_resources(iptables_rules, 'ipv4') +
      gather_resources(ip6tables_rules, 'ipv6')
  end

  def self.prefetch(resources)
    instances.each do |prov|
      if (resource = resources[prov.name])
        resource.provider = prov
      end
    end
  end

  def policy_insync?
    @needs_sync = []

    self.class.instances.each do |inst|
      next unless inst.policy != resource[:policy]
      next unless (inst.table == resource[:table]) && (inst.chain == resource[:chain])
      if Array(resource[:apply_to]).include?(inst.apply_to)
        @needs_sync << inst.apply_to
      end
    end

    @needs_sync.empty?
  end

  def flush
    if needs_sync.include?('ipv4')
      iptables(['-t', @resource[:table], '-P', @resource[:chain], @resource[:policy]])
    end

    return unless needs_sync.include?('ipv6')
    ip6tables(['-t', @resource[:table], '-P', @resource[:chain], @resource[:policy]])
  end

  private

  def self.iptables_rules
    iptables_save.lines.map(&:strip)
  end

  def self.ip6tables_rules
    if Facter.value(:ipv6_enabled)
      ip6tables_save.lines.map(&:strip)
    else
      []
    end
  end

  def self.gather_resources(rules, rule_type)
    valid_tables = ['filter']

    resources = []

    current_table = nil
    rules.each do |rule|
      if rule =~ %r{^\*(.*)}
        current_table = Regexp.last_match(1).strip
        next
      end

      next unless valid_tables.include?(current_table)
      chain, policy = rule.split(%r{\s+})

      next unless ['ACCEPT', 'DROP'].include?(policy)
      chain.delete!(':')

      resource = {
        name: "#{current_table}:#{chain}",
        table: current_table,
        chain: chain,
        policy: policy,
        apply_to: rule_type,
      }

      resources << new(resource)
    end

    resources
  end
end
