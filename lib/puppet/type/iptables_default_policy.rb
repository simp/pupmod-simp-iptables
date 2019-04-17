Puppet::Type.newtype(:iptables_default_policy) do
  @doc = 'Manage the default policy on iptables tables built-in chains'

  def initialize(*args)
    super(*args)

    self[:tag] = ['iptables','ip6tables']
  end

  newparam(:name) do
    desc 'A name of the form <table>:<chain> to which the resource will be applied'

    # Prevent conflicting resources with different case names
    munge do |value|
      value.downcase
    end
  end

  newparam(:apply_to, :array_matching => :all) do
    desc "What version(s) of iptables to which to apply this rule.
          'all' is equivalent to ['ipv4', 'ipv6'] as appropriate."

    newvalues(:ipv4, :ipv6, :all)
    defaultto 'all'

    munge do |value|
      value = ['ipv4', 'ipv6'] if value == 'all'
      value
    end
  end

  newparam(:table) do
    isnamevar
    desc 'The table that the chain belongs to'

    munge do |value|
      value.downcase
    end
  end

  newparam(:chain) do
    isnamevar
    desc 'The targeted chain'

    munge do |value|
      value.upcase
    end
  end

  newproperty(:policy) do
    newvalues 'ACCEPT', 'DROP', 'accept', 'drop'

    defaultto 'DROP'

    munge do |value|
      value.upcase
    end

    def insync?(is)
      provider.policy_insync?
    end

    def change_to_s(from,to)
      return %{Default policy changed to '#{to}' for '#{provider.needs_sync.join(', ')}'}
    end
  end

  autorequire(:iptables_optimize) do
    catalog.resources.find_all { |r|
      r.is_a?(Puppet::Type.type(:iptables_optimize))
    }.flatten
  end

  validate do
    ipv4_tables = {
      'filter' => [
        'INPUT',
        'FORWARD',
        'OUTPUT'
      ],
    }

    ipv6_tables = {
      'filter' => [
        'INPUT',
        'FORWARD',
        'OUTPUT'
      ]
    }

    errmsg = []

    if parameters[:apply_to].value.include?('ipv4')
      v4_chains = ipv4_tables[parameters[:table].value]

      if v4_chains
        unless v4_chains.include?(parameters[:chain].value)
          errmsg << "Invalid chain '#{parameters[:chain].value}' in table '#{parameters[:table].value}' for IPv4"
          errmsg << "  Valid chains include '#{v4_chains.join("', '")}'"
        end
      else
        errmsg << "Invalid table '#{parameters[:table].value}' for IPv4"
        errmsg << "  Valid tables include '#{ipv4_tables.keys.join("', '")}'"
      end
    end

    if parameters[:apply_to].value.include?('ipv6')
      v6_chains = ipv6_tables[parameters[:table].value]

      if v6_chains
        unless v6_chains.include?(parameters[:chain].value)
          errmsg << "Invalid chain '#{parameters[:chain].value}' in table '#{parameters[:table].value}' for IPv6"
          errmsg << "  Valid chains include '#{v6_chains.join("', '")}'"
        end
      else
        errmsg << "Invalid table '#{parameters[:table].value}' for IPv6"
        errmsg << "  Valid tables include '#{ipv6_tables.keys.join("', '")}'"
      end
    end

    fail(Puppet::Error, errmsg.join("\n")) unless errmsg.empty?
  end

  def self.title_patterns
    [
      [
        /^(.*):(.*)$/,
        [
          [:table],
          [:chain]
        ]
      ]
    ]
  end
end
