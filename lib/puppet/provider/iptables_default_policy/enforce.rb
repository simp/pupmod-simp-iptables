Puppet::Type.type(:iptables_default_policy).provide(:enforce) do

  desc 'Provider for manging the default iptables policies'

  commands :iptables      => 'iptables'
  commands :iptables_save => 'iptables-save'

  optional_commands :ip6tables      => 'ip6tables'
  optional_commands :ip6tables_save => 'ip6tables-save'

  mk_resource_methods

  attr_reader :needs_sync

  def self.instances
    gather_resources(iptables_rules, 'ipv4') +
      gather_resources(ip6tables_rules, 'ipv6')
  end

  def self.prefetch(resources)
    instances.each do |prov|
      if resource = resources[prov.name]
        resource.provider = prov
      end
    end
  end

  def policy_insync?
    @needs_sync = []

    self.class.instances.each do |inst|
      if inst.policy != resource[:policy]
        if (inst.table == resource[:table]) && (inst.chain == resource[:chain])
          if Array(resource[:apply_to]).include?(inst.apply_to)
            @needs_sync << inst.apply_to
          end
        end
      end
    end

    return @needs_sync.empty?
  end

  def flush
    if needs_sync.include?('ipv4')
      iptables(['-t', @resource[:table], '-P', @resource[:chain], @resource[:policy]])
    end

    if needs_sync.include?('ipv6')
      ip6tables(['-t', @resource[:table], '-P', @resource[:chain], @resource[:policy]])
    end
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
      if rule =~ /^\*(.*)/
        current_table = $1.strip
        next
      end

      if valid_tables.include?(current_table)
        chain, policy = rule.split(/\s+/)

        if ['ACCEPT', 'DROP'].include?(policy)
          chain.delete!(':')

          resource = {
            :name     => "#{current_table}:#{chain}",
            :table    => current_table,
            :chain    => chain,
            :policy   => policy,
            :apply_to => rule_type
          }

          resources << new(resource)
        end
      end
    end

    return resources
  end
end
