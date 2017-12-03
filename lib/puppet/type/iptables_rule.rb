Puppet::Type.newtype(:iptables_rule) do
  @doc = "Authoritatively manage iptables rules.  This type is
          atomic, either all rules work, or the old rules are
          preserved."

  def initialize(args)
    super

    self[:tag] = ['iptables','ip6tables']
  end

  newparam(:name) do
    isnamevar
    desc "The name of the rule. Simply used for creating the unique fragments."
  end

  newparam(:comment) do
    desc "A comment to add to the rule. 'SIMP:' Will be prepended to the comment for tracking."
    defaultto ""

    munge do |value|
      # IPTables can only take comments up to 256 characters.
      value = ('SIMP: ' + value).strip

      value[0..255]
    end
  end

  newparam(:header) do
    desc "Whether or not to auto-include the table LOCAL-INPUT in
          the rule."
    newvalues(:true,:false)
    defaultto 'true'

    munge do |value|
      value.to_s
    end
  end

  newparam(:apply_to) do
    desc "What version(s) of iptables to which to apply this rule.
          If set to 'auto' (the default) then we'll try to guess
          what you want and default to ['ipv4','ipv6'].

          If 'auto' is set then each line will be evaluated as an
          independent rule.
          - Any rules that have IPv4 addresses will be applied to
            iptables.
          - Any rules that have IPv6 addresses will be applied to
            ip6tables.
          - All other rules will be applied to *both* utilities.
          - If in doubt, split your rules and specify your tables!"
    newvalues(:ipv4,:ipv6,:all,:auto)
    defaultto 'auto'

    munge do |value|
      if value == 'all' then
        value = ['ipv4','ipv6']
      end
      value
    end
  end

  newparam(:table) do
    desc "The name of the table that you are adding to."
    defaultto :filter
  end

  newparam(:first) do
    desc "Set to 'true' if you want to prepend your rule."
    newvalues(:true,:false)
    defaultto :false
  end

  newparam(:absolute) do
    desc "Set to 'true' if you want the rule to be the absolute
          first or last. This is relative and places items in
          alphabetical order if multiple absolute first/lasts are
          specified."
    newvalues(:true,:false)
    defaultto :false
  end

  newparam(:order) do
    desc "The order in which the rule should appear. 1 is the
          minimum and 999 is the max."
    newvalues(/\d+/)
    defaultto '11'

    munge do |value|
      if resource[:first].to_s == 'true' then
        debug("Setting :order to 1 due to 'first'")
        value = '1'
      elsif value.to_i < 1 then
        debug("Setting :order to 1")
        value = '1'
      elsif value.to_i > 999 then
        debug("Setting :order to 999")
        value = '999'
      end

      if resource[:absolute].to_s == 'true' then
        if resource[:first].to_s == 'true' then
          debug("Setting :order to absolute first")
          value = '0'
        else
          debug("Setting :order to absolute last")
          value = '999'
        end
      end
      value
    end
  end

  newparam(:resolve) do
    desc "Whether or not to use DNS resolution to identify hostnames
          in IPTables statements.

          This should probably be left at :true since it is a rare
          scenario and, should you use this, you will want the rule
          to go into either iptables or ip6tables correctly.

          With this enabled, the IP address that is resolved will be
          added to IPTables and not the hostname itself."

    newvalues(:true,:false)
    defaultto :true
  end

  newproperty(:content) do
    desc "The content of the rule that should be added"
    newvalues(/\w+/)

    def change_to_s(current_value, new_value)
      if current_value && current_value.is_a?(Array) && !current_value.empty?
        return "#{current_value.join(' and ')} rules changed."
      else
        super
      end
    end
  end
end
