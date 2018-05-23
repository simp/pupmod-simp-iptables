Puppet::Type.type(:iptables_rule).provide(:manage) do

  desc "Provider for the atomic management of iptables rules with
        optional rule preservation."

  commands :iptables  => 'iptables'
  commands :ip6tables => 'ip6tables'

  def self.load_rules(table_type)
    old_rules = ''

    if File.readable?(iptables_rules[table_type][:target_file])
      File.open(iptables_rules[table_type][:target_file],'r') { |fh|
        old_rules = fh.read.chomp
      }
    end

    iptables_rules[table_type][:old_content] = old_rules

    # Split them up for comparison later.
    current_table = ''
    old_rules.each_line do |line|
      line.strip!

      next if line =~ /^\s*$/
      next if line[0].chr == '#'
      next if (line[0].chr == '*') && (current_table = line[1..-1].to_sym)

      iptables_rules[table_type][:old_content_hash][current_table] ||= []
      iptables_rules[table_type][:old_content_hash][current_table] << line
    end
  end

  def self.iptables_rules
    return @iptables_rules if @iptables_rules

    @iptables_rules = {
      :iptables         => {
        :target_file      => '/etc/sysconfig/.iptables_puppet',
        :old_content      => '',
        :old_content_hash => {},
        :new_content      => {},
        :valid_tables     => [:nat, :filter, :mangle, :raw]
      },
      :ip6tables        => {
        :target_file      => '/etc/sysconfig/.ip6tables_puppet',
        :old_content      => '',
        :old_content_hash => {},
        :new_content      => {},
        :valid_tables     => [:filter, :mangle, :raw]
      },
      # The types of tables that we can handle. Mostly for iteration.
      :table_types      => [
        :iptables,
        :ip6tables
       ],
      :initialized      => false,
      :num_resources    => 0,
      :num_runs         => 0
    }

    @iptables_rules[:table_types].each do |table_type|
      load_rules(table_type)
    end

    return @iptables_rules
  end

  def self.post_resource_eval
    # Clean up our cruft
    @iptables_rules = nil
  end

  def iptables_rules
    self.class.iptables_rules
  end

  def initialize(*args)
    require 'puppetx/simp/simplib'
    require 'puppetx/simp/iptables'

    super(*args)
  end

  def content
    iptables_rules[:num_runs] += 1

    if iptables_rules[:num_resources] == 0
      iptables_rules[:num_resources] =
        resource.catalog.resources.find_all{ |x|
          x.is_a?(Puppet::Type.type(:iptables_rule))
        }.count
    end

    # Process the content.
    # We may have multi-line content.
    parsed_rule = {}
    content_lines = resource[:content].split("\n")
    content_lines.each_with_index do |content_line,i|
      content_line.strip!

      if resource[:header] != 'false'
        debug("Adding default header: -A LOCAL-INPUT")
        # Only add the header if we don't have one already.
        if content_line !~ /\s*-(A|D|I|R|N|P)\s+/
          content_line = "-A LOCAL-INPUT #{content_line}"
        end
      end

      if !resource[:comment].to_s.empty?
        debug("Adding comment #{resource[:comment]}")
        content_line = "#{content_line} -m comment --comment \"#{resource[:comment]}\""
      end

      # This should be set if the resolution code below replaces the running
      # rule with one that is resolved.
      rule_replaced = false

      # We need to do DNS resolution on any hostnames that are passed
      # via the -s/--source or -d/--destination addresses.
      if resource[:resolve] == :true
        if content_line =~ /(.*(?:-s|--source|-d|--destination)\s+)(.*?)(\s+.*)/
          prefix = $1
          check_list = $2
          suffix = $3

          check_list = check_list.split(',')
          check_list.each do |to_check|
            unless ipaddr?(to_check)
              require 'resolv'

              addresses = []
              begin
                Puppet.debug("Resolving '#{to_check}' via Hosts")
                addresses = Resolv::Hosts.new.getaddresses(to_check)

                if addresses.empty?
                  Resolv::DNS.open do |dns|
                    Puppet.debug("Resolving '#{to_check}' via DNS")
                    addresses = dns.getresources(to_check,Resolv::DNS::Resource::IN::A).map{|x| x.address.to_s}.sort
                    addresses += dns.getresources(to_check,Resolv::DNS::Resource::IN::AAAA).map{|x| x.address.to_s}.sort
                  end
                end
              rescue Resolv::ResolvError => e
                resolv_failure = true
              rescue Resolv::ResolvTimeout => e
                Puppet.warning("Timeout when resolving #{to_check}, commenting out: #{e}")
                content_line = "# DNS Timeout Failure: #{content_line}"
              rescue Exception => e
                Puppet.warning("Unknown DNS issue for #{to_check}, commenting out: #{e}")
                content_line = "# Unknown DNS issue: #{content_line}"
              end

              if resolv_failure or addresses.empty?
                Puppet.warning("Could not resolve #{to_check}, commenting out: #{e}")
                content_line = "# DNS Resolution Failure: #{content_line}"
              else
                rule_replaced = true

                addresses.each_with_index do |addr,j|
                  new_rule = "#{prefix}#{addr}#{suffix}"
                  apply_to?(new_rule).each do |rule_type|
                    rule_type = rule_type.to_sym

                    parsed_rule[rule_type] ||= []
                    parsed_rule[rule_type] << new_rule
                  end
                end
              end
            end
          end
        end
      end

      unless rule_replaced
        apply_to?(content_line).each do |rule_type|
          rule_type = rule_type.to_sym

          parsed_rule[rule_type] ||= []
          parsed_rule[rule_type] << content_line
        end
      end
    end

    parsed_rule.keys.each do |key|
      table = resource[:table].to_sym

      iptables_rules[key][:new_content][table] ||= {
        :chains => {},
        :rules => {}
      }
      # The following pulls out the chain lines and auto-detects any
      # chains such that we can put the rules together properly
      # later.
      # The chain lines are also removed from the rule content so that
      # everything can be put in its proper place later.
      parsed_rule[key].delete_if{|x|
        x.chomp!

        # Strip off and store the valid existing chain lines (if any)
        if x =~ /^(:.*?)\s+(.*?)\s+/
          iptables_rules[key][:new_content][table][:chains][$1] = "#{$2} [0:0]"
        end
      }
      iptables_rules[key][:new_content][table][:rules]["#{resource[:order]}_#{resource[:name]}"] = parsed_rule[key].join("\n")
    end

    if iptables_rules[:num_runs] == iptables_rules[:num_resources]
      # Here, we put together the new content for all known content.
      changed = []
      iptables_rules[:table_types].each do |table_type|
        # This may be bad form, but we're discarding the :new_content
        # hash and simply holding a string for comparison and writing
        # purposes at this point.
        iptables_rules[table_type][:new_content] = collate_output(table_type)

        Puppet.debug("Content Diff for *#{table_type}:\n" +
          "  Old: #{iptables_rules[table_type][:old_content]}\n" +
          "  New: #{iptables_rules[table_type][:new_content]}"
        )

        # Actually do the comparison between the old and the new to
        # see if things changed.
        if (
          iptables_rules[table_type][:new_content] !=
          iptables_rules[table_type][:old_content]
        )
        then
          changed << table_type
        end
      end

      # If we didn't change anything, just spoof out the return.
      if changed.empty?
        return resource[:content]
      else
        return changed
      end
    end

    # If we got here, we're not ready to potentially change anything yet.
    return resource[:content]
  end

  def content=(should)
    # Nothing to do here.
  end

  def flush
    iptables_rules[:table_types].each do |table_type|
      File.open(iptables_rules[table_type][:target_file],'w') { |fh|
        fh.rewind

        fh.puts(iptables_rules[table_type][:new_content])
      }
      File.chmod(0600,iptables_rules[table_type][:target_file])
    end

    iptables_rules[:initialized] = false
  end

  private

  # Returns an IPAddr object if the passed object is a valid IP
  # address.
  def ipaddr?(to_check)
    ipaddr = nil
    begin
      ipaddr = IPAddr.new(to_check)
    rescue Exception
      # Not an IP address, ignore.
    end

    ipaddr
  end

  # Takes an iptables line and returns an array of utilities to
  # which to apply the line.
  def apply_to?(line)
    # Find something that looks like an IP address and see if it
    # parses.
    targets = Array(resource[:apply_to])
    retval = []

    # We need to check all of the strings for content.
    line.split.each do |i|
      ip_check = ipaddr?(i)
      if ip_check
        #TODO: Clean this up when we move to puppet4
        #Had to check for 0 or more digits followed by a colon
        #to account for bad ipv6 formation in ruby 1.8.7
        if ip_check.ipv6? && (i =~ /\d*:+/)
          retval = [:ip6tables]
        else
          retval = [:iptables]
        end
        break
      end
    end

    if retval.empty?
      if targets.include?('ipv4')
        retval << :iptables
      end
      if targets.include?('ipv6')
        retval << :ip6tables
      end
      if retval.empty?
        retval = [:iptables,:ip6tables]
      end
    end

    if (targets.to_s == 'ipv4') && !retval.include?(:iptables)
      fail Puppet::Error,"#{line} does not appear to be an IPv4 address"
    elsif (targets.to_s == 'ipv6') && !retval.include?(:ip6tables)
      fail Puppet::Error,"#{line} does not appear to be an IPv6 address"
    end

    # Here, we remove any target that does not have a valid table.
    iptables_rules[:table_types].each do |table|
      unless iptables_rules[table][:valid_tables].include?(resource[:table].to_sym)
        Puppet.debug("Ignoring ':#{resource[:table]}' since it is not valid for :#{table}")
        retval.delete(table)
      end
    end

    retval
  end

  def collate_output(rule_type)
    output = []

    iptables_rules[rule_type][:new_content].keys.sort.each { |table|
      # First, we have to list the filter name.
      output << "*#{table}"

      # Run through the rules and make sure we have all of the
      # referenced chains.
      #
      # If we've never actually run this before, then the old content
      # will be nil so we just cast it to an empty Array.
      (
        iptables_rules[rule_type][:new_content][table][:rules].values +
        Array(iptables_rules[rule_type][:old_content_hash][table])
      ).each do |x|
        # Could have a multi-line rule!
        x.each_line do |rule_line|
          chain = PuppetX::SIMP::IPTables::Rule.parse(rule_line)[:chain]
          iptables_rules[rule_type][:new_content][table][:chains][":#{chain}"] = nil unless chain.nil?
        end
      end

      # Now, we have to stick on the chain names.
      # This needs to stay sorted so that we don't end up reloading
      # iptables every time.
      output << iptables_rules[rule_type][:new_content][table][:chains].keys.sort.collect{|key|
        value = iptables_rules[rule_type][:new_content][table][:chains][key]
        if value
          key = "#{key} #{value}"
        else
          "#{key} - [0:0]"
        end
      }.join("\n")

      # Properly sort our rules.
      output << iptables_rules[rule_type][:new_content][table][:rules].keys.sort_by { |x|
        PuppetX::SIMP::Simplib.human_sort(x)
      }.collect { |x|
        iptables_rules[rule_type][:new_content][table][:rules][x]
      }.join("\n")

      # Make sure we have a commit for each table
      output << 'COMMIT'
    }

    return PuppetX::SIMP::IPTables.new(output.join("\n")).to_s
  end
end
