Puppet::Type.newtype(:iptables_optimize) do
  @desc = 'Optimize managed iptables rules.'

  newparam(:name, namevar: true) do
    desc 'The path to the target file to be optimized. Mainly used for ensuring that the file comes after the optimization.'
  end

  newparam(:disable) do
    desc <<~EOM
      This is a way to authoritatively disable the application of the
      iptables module.
    EOM

    newvalues(:true, :false)
    defaultto(:false)
  end

  newparam(:precise_match) do
    desc <<~EOM
      Instead of matching rule counts, perform a more precise match against the
      running and to-be-applied rules. You may find that minor changes, such as
      a simple netmask change will not be enforced without enabling this option.

      This is enabled by default because it is a more correct approach.

      * NOTE: You **MUST** use the exact same syntax that will be returned by
        `iptables-save` if you enable this option!
      * For example, you cannot write `echo-request` for an ICMP echo match, you
        must instead use `8`.
    EOM

    newvalues(:true, :false)
    defaultto(:true)
  end

  newparam(:ignore) do
    desc <<~EOM
      Ignore all *running* iptables rules matching one or more provided Ruby
      regexes. The regexes are compared against the jump and chain options, as
      well as the interface name of the running rules and excluded from the
      synchronization comparison against the new rules.

      !!Do not include the beginning and ending slashes in your regular expressions.!!

      NOTE: If a rule has been added or removed, this setting ignored and
      iptables *will* be restarted! If you have services which are
      affected by this, make sure that they subscribe to
      Service['iptables'] and/or Service['ip6tables'] as appropriate.

      Examples:
        # Preserve all rules whose jump or chain begins with the word 'foo'
        ignore => '^foo'

        # Preserve all rules whose jump or chain begins with the word 'foo' or
        # ends with the word 'bar'
        ignore => ['^foo','bar$']
    EOM

    munge do |value|
      if value.empty?
        value = []
      else
        begin
          value = Array(value).map { |x| Regexp.new(x) }
        rescue RegexpError
          raise Puppet::ParseError, "Regex: '#{value[key]}' has an invalid regex at key '#{key}'"
        end
      end

      value
    end
  end

  newproperty(:optimize) do
    desc 'Whether or not to optimize'
    newvalues(:true, :false)
    defaultto :true

    def insync?(is)
      if resource[:disable] == :true
        debug('IPTables administratively disabled due to setting $disable in iptables_optimize')
        return true
      end

      is_cmp = is
      is_cmp = :true if is == :optimized

      if is_cmp != should
        @rules_differ = true
      elsif !provider.system_insync?
        @running_rules_out_of_sync = true
      end

      (@rules_differ || @running_rules_out_of_sync) ? false : true
    end

    def change_to_s(_from, _to)
      if @rules_differ
        'System rules have changed'
      elsif @running_rules_out_of_sync
        'Active rules do not match configured rules'
      end
    end
  end

  autorequire(:iptables_rule) do
    req = []
    resource = catalog.resources.select do |r|
      r.is_a?(Puppet::Type.type(:iptables_rule))
    end
    unless resource.empty?
      req << resource
    end
    req.flatten!
    req.each { |r| debug "Autorequiring #{r}" }
    req
  end

  autorequire(:service) do
    ['firewalld']
  end

  autonotify(:file) do
    [self[:name]]
  end

  autonotify(:service) do
    ['iptables']
  end
end
