module PuppetX
  module SIMP
    class IPTables

      require 'puppetx/simp/iptables/rule'

      attr_reader :rules

      def initialize(rules)
        current_table = nil

        # These are generally useful things to have around.
        #
        # The @tables Hash is a way to reference arrays of rules based on the
        # table that contains the rule.
        #
        # The @rules Array is an ordered array of Rule objects
        #
        @tables = {}
        @rules = []

        rules.chomp.split("\n").each do |rule|
          next if rule =~ /^\s*(#.*)?$/

          if rule =~ /^\s*(\*.*)/
            current_table = $1.strip
            @tables[current_table] ||= []
            next
          end

          rule = PuppetX::SIMP::IPTables::Rule.new(rule,current_table)

          @tables[current_table] << rule
          @rules << rule
        end
      end

      def to_s
        result = []

        @tables.keys.sort.each do |table|
          result << table

          @tables[table].each do |rule|
            result << rule
          end
        end

        result.join("\n")
      end

      # Return a list of all chains used by a rule in this ruleset with a chain
      # or jump segment matching the optional Array of compiled regular
      # expressions.
      #
      # If no Array is passed, all results will be returned.
      #
      def chains(to_match = [])
        to_match ||= []
        result = {}

        @rules.each do |rule|
          next unless rule.chain

          if to_match.empty?
            result[rule.chain] = true
          else
            to_match.each do |regex|
              if regex.match(rule.chain) || regex.match(rule.jump)
                result[rule.chain] = true
              end
            end
          end
        end

        return result.keys.sort
      end

      # This returns the rules in a format suitable for direct application
      # using subsequent calls to the iptables command.
      #
      # Ensure that we DO NOT flush any chains that are only simple rules!
      #
      # 'protect' is an Array of chains that should never be flushed.
      #
      def live_format(protect=[])
        protect ||= []
        result = []
        flushed_chains = {}
        created_chains = []

        @rules.each do |rule|
          if rule.rule_type == :rule
            table = rule.table.split('*').last

            unless created_chains.include?(rule.chain)
              result.unshift("-N #{rule.chain} 2>/dev/null")
              created_chains << rule.chain
            end

            unless (protect.include?(rule.chain) || flushed_chains[rule.chain])
              result << "-t #{table} -F #{rule.chain}"
              flushed_chains[rule.chain] = true
            end

            result << "-t #{table} " + rule.to_s
          end
        end

        result
      end

      # Return a hash of rules of the following format:
      #
      #   <table_name> => [rule1, rule2, etc...]
      #
      def to_hash
        result = {}
        @tables.keys.sort.each do |table|
          result[table] ||= []

          result[table] << @tables[table].map{|rule| rule = rule.to_s}
        end

        return result
      end

      # Produces a hash-based report on the number of iptables rules, and type
      # of operation in a given chain.
      #
      # You may optionally pass an array of compiled regular expressions. If
      # this array is present, all items with a chain or jump matching the
      # regex will be ignored.
      #
      def report(to_ignore=[])
        result = {}

        @tables.keys.each do |table|
          result[table] ||= {}

          @tables[table].each do |rule|
            next unless rule.rule_type == :rule

            do_ignore = false
            to_ignore.each do |ignore|
              if [rule.chain, rule.jump, rule.input_interface, rule.output_interface].find {|x| ignore.match(x)}
               do_ignore = true
               break
              end
            end

            next if do_ignore

            result[table][rule.chain] ||= {}

            # Need a unique key target for precise matches
            tgt_key = [rule.input_interface, rule.output_interface, rule.jump].compact.join('|')

            unless tgt_key.empty?
              result[table][rule.chain][tgt_key] ||= 0
              result[table][rule.chain][tgt_key] += 1
            end
          end
        end

        result
      end

      def optimize
        new_rules = []

        # Hard coded limit in iptables multiport rules.
        max_ports = 15

        @tables.keys.sort.each do |table|
          new_rules << table

          @tables[table].each do |rule|
            rule = rule.to_s

            if new_rules.empty?
              new_rules << rule
              next
            end

            # Make sure we have a valid rule for multiport compression.
            if  rule !~ /-p(rotocol)?\s+(ud|tc)p/ &&
                rule !~ /--(d(estination-)?|s(ource-)?)ports?\s+/
            then
              new_rules << rule
              next
            end

            last_rule = new_rules.pop

            prev_ports = []
            new_ports = []
            prev_multiport = false
            port_type = nil

            prev_rule = last_rule.split(/\s+-/).delete_if{ |x|
              retval = false
              if x.empty?
                retval = true
              elsif x =~ /m(ulti)?port/
                prev_multiport = true
                retval = true
              elsif x =~ /(d(estination-)?|s(ource-)?)ports?\s+(.*)/
                port_type = $1[0].chr
                prev_ports += $4.split(',')
                retval = true
              end
              retval
            }

            new_rule = rule.split(/\s+-/).delete_if{ |x|
              retval = false
              if x.empty? || x =~ /m(ulti)?port/
                retval = true
              elsif x =~ /(d(estination-)?|s(ource-)?)ports?\s+(.*)/
                # Add ranges as sub-arrays.
                new_ports += $4.split(',')
                retval = true
              end
              retval
            }

            new_rule.map!{|x| x = normalize_rule(x)}
            prev_rule.map!{|x| x = normalize_rule(x)}

            if (new_rule.sort <=> prev_rule.sort) == 0
              Puppet.debug("Rule:\n  #{new_rule} matches\n  #{prev_rule}")
              # Flatten when comparing sizes to account for ranges.
              new_ports = (prev_ports + new_ports).uniq
              slice_array(new_ports,max_ports).each do |sub_ports|
                new_rules << prev_rule.dup.insert(-2,"m multiport --#{port_type}ports #{sub_ports.sort.uniq.join(',')}").join(' -')
              end
            else
              Puppet.debug("No match for: #{rule}")
              new_rules << last_rule
              new_rules << rule
            end
          end
        end

        return PuppetX::SIMP::IPTables.new(new_rules.join("\n"))
      end

      private

      def slice_array(to_slice, max_length)
        max_length = max_length.to_i
        to_slice = Array(to_slice).flatten

        cluster_locations = to_slice.collect{|x| x.to_s.include?(':')}

        to_slice = to_slice.map{|x| x.to_s.split(':')}.flatten

        num_groups = to_slice.length/max_length
        unless (to_slice.length % max_length) == 0
          num_groups += 1
        end

        retval = []
        (0...num_groups).each do |x|
          retval << to_slice[(x * max_length)..((x * max_length) + max_length - 1)].compact
        end

        i = 0
        retval.each do |arr|
          arr.each_with_index do |x,j|
            if cluster_locations[i]
              arr[j] = "#{arr[j]}:#{arr[j+1]}"
              arr.delete_at(j+1)
            end
            i += 1
          end
        end

        return retval
      end

      def normalize_rule(rule)
        # Normalize Addresses for Comparison
        # Needs  a pre-split rule as an argument.
        if rule =~ /^(s(ource)?|d(estination)?)\s+(.*)/
          if $1
            opt = $1[0].chr
            addr = $4
            begin
              ipaddr = IPAddr.new(addr)
              rule = "#{opt} #{ipaddr}/#{ipaddr.inspect.split('/').last.chop}"
            rescue ArgumentError,NoMethodError
              # If it's a bad address, or something was nil, just return the rule.
              # We should never get here.
            end
          end
        end

        return rule
      end
    end
  end
end
