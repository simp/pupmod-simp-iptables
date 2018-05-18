module PuppetX
  module SIMP
    class IPTables

      require 'puppetx/simp/iptables/rule'

      def initialize(rules_str)
        # The @tables Hash is a way to reference arrays of rules based on the
        # table that contains the rule.

        @tables = { }

        new_rules = []

        current_table = nil
        rules_str.chomp.split("\n").each do |rule|
          # Skip Inline Comments
          next if rule =~ /^\s*(#.*)?$/

          if rule =~ /^\s*\*/
            # New tables means new rules
            @tables[current_table][:rules] = sort_rules(new_rules) unless new_rules.empty?

            current_table = add_table(rule)

            new_rules = []

            next
          end

          if current_table
            rule = PuppetX::SIMP::IPTables::Rule.new(rule, current_table)

            if rule
              if rule.rule_type == :chain
                @tables[current_table][:chains] << rule
              elsif rule.rule_type == :rule
                new_rules << rule
              end
            end
          end
        end

        # Need to sort the last set of rules in the stack
        @tables[current_table][:rules] = sort_rules(new_rules) unless new_rules.empty?

        prune_chains!
      end

      # A comparator for two rulesets
      def ==(to_cmp)
        # Fast matching
        unless tables == to_cmp.tables
          Puppet.debug('Tables differ between rulesets')
          return false
        end

        unless report == to_cmp.report
          Puppet.debug('Reports differ between rulesets')
          return false
        end

        # Comprehensive search
        tables.each do |table|
          unless rules(table) == to_cmp.rules(table)
            Puppet.debug("Rules in table '#{table}' differ")
            return false
          end
        end
      end

      # Sort a list of rules into the same order that `iptables-save` uses on
      # output
      #
      # @param to_sort [Array[PuppetX::SIMP::IPTables::Rule]]
      #
      # @return [Array[PuppetX::SIMP::IPTables::Rule]]
      #
      def sort_rules(to_sort)
        ordered_chains = to_sort.collect{|r| r.chain}.uniq

        ordered_rules = []

        ordered_chains.each do |chain|
          ordered_rules += to_sort.select{|r| r.chain == chain}
        end

        return ordered_rules
      end

      # Return all IPTables 'tables'
      #
      # @return [Array[String]]
      #
      def tables
        return @tables.keys.sort
      end

      # Merge the passed IPTables object with the current object
      #
      # This involves adding all chains from the passed object and
      # **prepending** all rules to the existing rules.
      #
      # @param iptables_obj [PuppetX::SIMP::IPTables]
      #   The IPTables object to be merged
      #
      # @return [PuppetX::SIMP::IPTables]
      #
      def merge(iptables_obj)
        return PuppetX::SIMP::IPTables.new(to_s).merge!(iptables_obj)
      end

      # The same behavior as `merge` but affecting the current object
      #
      # @param iptables_obj [PuppetX::SIMP::IPTables]
      #   The IPTables object to be merged
      #
      def merge!(iptables_obj)
        iptables_obj.tables.each do |table|
          add_chains(table, iptables_obj.chains(table))
          prepend_rules(table, iptables_obj.rules(table))
        end

        prune_chains!

        return self
      end

      # Add the passed 'table' to the list of tables
      #
      # @param table [String]
      #
      # @return [String]
      #   The passed table
      #
      def add_table(table)
        if table =~ /^\s*(\*.*)/
          @tables[$1.strip] ||= { :chains => [], :rules => [] }
        else
          fail "Table '#{table}' must start with a '*'"
        end

        return table
      end

      # Return all 'chains' for the given table
      #
      # @param table [String]
      #   The table from which to return the chains
      #
      # @return [Array[PuppetX::SIMP::IPTables::Rule]]
      #
      def chains(table)
        return @tables[table][:chains]
      end

      # Add chains to the passed table
      #
      # @param table [String]
      #   The table to which to add the chains
      #
      # @param new_chains [Array[<PuppetX::SIMP::IPTables::Rule, String>]]
      #   Chains that should be added to the table
      #
      def add_chains(table, new_chains)
        Array(new_chains).each do |chain|
          if chain.is_a?(String)
            if chain[0].chr == ':'
              chain = PuppetX::SIMP::IPTables::Rule.new(chain, table)
            else
              chain = PuppetX::SIMP::IPTables::Rule.new(':' + chain + ' - [0:0]', table)
            end
          end

          if chain.is_a?(PuppetX::SIMP::IPTables::Rule)
            process_chain(chain)

            if !chains(table).find { |x| x.chain == chain.chain }
              @tables[table][:chains].push(chain)
            end
          else
            fail "chain must be a PuppetX::SIMP::IPTables::Rule or a String not #{chain.class}"
          end
        end
      end

      # Remove any chains from the tables that do not have a matching rule
      def prune_chains!
        all_chains = @tables.collect { |key, value|
          @tables[key][:rules]
        }.
        flatten.map { |rule|
          new_rule = [rule.chain]
          new_rule << rule.jump if rule.jump
        }.flatten.uniq

        tables.each do |table|
          chains_to_keep = []

          chains(table).each do |chain|
            if all_chains.include?(chain.chain)
              chains_to_keep << chain
            end
          end

          @tables[table][:chains] = chains_to_keep
        end

        return self
      end

      # Return all 'rules' for the given table
      #
      # @param table [String]
      #   The table from which to return the rules
      #
      # @return [Array[PuppetX::SIMP::IPTables::Rule]]
      #
      def rules(table)
        return @tables[table][:rules]
      end

      # Prepend rules to the existing rules while preserving chain order
      #
      # @param table [String]
      #   The table to which to add the chains
      #
      # @param new_rules [Array[<PuppetX::SIMP::IPTables::Rule, String>]]
      #   Rules that should be prepended to the table
      #
      def prepend_rules(table, new_rules)
        Array(new_rules).each do |rule|
          if rule.is_a?(String)
            rule = PuppetX::SIMP::IPTables::Rule.new(rule)
          end

          if rule.is_a?(PuppetX::SIMP::IPTables::Rule)
            process_rule(rule)

            if @tables[table][:rules].empty?
              @tables[table][:rules] << rule
            else
              start_index = @tables[table][:rules].index{|x| x.chain == rule.chain} || 0

              unless rule == @tables[table][:rules][start_index]
                @tables[table][:rules].insert(start_index, rule)
              end
            end
          else
            fail "rule must be a PuppetX::SIMP::IPTables::Rule not #{rule.class}"
          end
        end
      end

      # Append rules to the existing rules while preserving chain order
      #
      # Will not add a duplicate rule to the chain
      #
      # @param table [String]
      #   The table to which to add the chains
      #
      # @param new_rules [Array[<PuppetX::SIMP::IPTables::Rule, String>]]
      #   Rules that should be appended to the table
      #
      def append_rules(table, new_rules)
        Array(new_rules).each do |rule|
          if rule.is_a?(String)
            rule = PuppetX::SIMP::IPTables::Rule.new(rule)
          end

          if rule.is_a?(PuppetX::SIMP::IPTables::Rule)
            process_rule(rule)

            if @tables[table][:rules].empty?
              @tables[table][:rules] << rule
            else
              end_index = @tables[table][:rules].rindex{|x| x.chain == rule.chain} || -2

              unless rule == @tables[table][:rules][end_index]
                end_index = end_index + 1

                @tables[table][:rules].insert(end_index, rule)
              end
            end
          else
            fail "rule must be a PuppetX::SIMP::IPTables::Rule not #{rule.class}"
          end
        end
      end

      # Return whether or not the table contains a matching rule
      #
      # @param table [String]
      #   The table to which to add the chains
      #
      # @param rule [PuppetX::SIMP::IPTables::Rule]
      #   The rule that is to be matched
      #
      # @return Boolean
      #
      def include_rule?(table, rule)
        rules(table).each do |current_rule|
          return true if current_rule == rule
        end

        return false
      end

      # Return a string that is ready for processing by the `iptables-restore`
      # command
      #
      # @return [String]
      #
      def to_s
        result = []

        tables.each do |table|
          result << table

          result += chains(table).map(&:rule)
          result += rules(table).map(&:rule)

          result << 'COMMIT'
        end

        result.join("\n")
      end

      # Identify rules to be preserved from all tables
      #
      # @param regex [Array[Regexp]]
      #   A list of regular expressions that should be matched against
      #
      # @param components [Array[String]]
      #   A list of the rule subcomponents that you want to match against all
      #   or any of the regular expressions
      #
      # @return PuppetX::SIMP::IPTables
      #
      def preserve_match(regex = [], components = ['chain', 'jump', 'input_interface', 'output_interface'])
        result = PuppetX::SIMP::IPTables.new('')

        @tables.each_key do |table|

          # Preserve all existing chains
          result.add_chains(table, chains(table))

          rules(table).each do |rule|
            # Ignore all rules dropped by SIMP
            next if (rule.rule_hash['comment'] && rule.rule_hash['comment'][:value].start_with?('SIMP:'))

            Array(regex).each do |cmp|
              Array(components).each do |component|
                val = rule.send(component)

                if cmp.match(val)
                  result.prepend_rules(table, rule)
                end
              end
            end
          end
        end

        return result
      end

      # Produces a hash-based report on the number of iptables rules, and type
      # of operation in a given chain.
      #
      # The report hash is simply a key to count match of each of the different
      # rule types for ease of comparison.
      #
      # You may optionally pass an array of compiled regular expressions. If
      # this array is present, all items with an interface, chain, or jump
      # matching the regex will be ignored.
      #
      # @param to_ignore [Array[Regexp]]
      #   Regular expressions that should be ignored
      #
      # @return [Hash]
      #
      def report(to_ignore=[])
        result = {}

        tables.each do |table|
          result[table] ||= {}

          rules(table).each do |rule|
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

      # Optimize all of the rules and return an optimized object
      #
      # Optimizations include:
      #   * Elimination of duplicate repeated rules
      #   * Collection of ports into multiport matches in rules where the rest
      #     of the rule is identical
      #
      # @return PuppetX::SIMP::IPTables
      #
      def optimize
        new_rules = PuppetX::SIMP::IPTables.new('')

        # Hard coded limit in iptables multiport rules.
        max_ports = 15

        tables.each do |table|
          new_rules.add_table(table)
          new_rules.add_chains(table, chains(table))

          existing_rules = rules(table)

          pending_rule = nil

          existing_rules.each_with_index do |rule, index|
            if pending_rule
              prev_ports = []
              new_ports = []
              prev_multiport = false
              port_type = nil

              prev_rule = PuppetX::SIMP::IPTables::Rule.new(
                pending_rule.to_s.split(/\s+-/).delete_if{ |x|
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
                }.join(' -'), table
              )

              new_rule = PuppetX::SIMP::IPTables::Rule.new(
                rule.to_s.split(/\s+-/).delete_if{ |x|
                  retval = false
                  if x.empty? || x =~ /m(ulti)?port/
                    retval = true
                  elsif x =~ /(d(estination-)?|s(ource-)?)ports?\s+(.*)/
                    # Add ranges as sub-arrays.
                    new_ports += $4.split(',')
                    retval = true
                  end
                  retval
                }.join(' -'), table
              )

              if new_rule == prev_rule
                Puppet.debug("Rule:\n  #{new_rule} matches\n  #{prev_rule}")
                # Flatten when comparing sizes to account for ranges.
                new_ports = (prev_ports + new_ports).uniq

                slice_array(new_ports, max_ports).each do |sub_ports|
                  pending_rule = PuppetX::SIMP::IPTables::Rule.new(prev_rule.dup.insert(-2,"m multiport --#{port_type}ports #{sub_ports.sort.uniq.join(',')}").join(' -'))

                  # If on the last rule, just write it out
                  if (index == (existing_rules.count - 1))
                    Puppet.debug("Adding: rule '#{pending_rule}' to table '#{table}'")
                    new_rules.append_rules(table, pending_rule)
                  end
                end
              else
                Puppet.debug("No match for: #{rule}")

                Puppet.debug("Adding: pending rule '#{pending_rule}' to table '#{table}'")
                new_rules.append_rules(table, pending_rule)

                Puppet.debug("Adding: rule '#{rule}' to table '#{table}'")
                new_rules.append_rules(table, rule)

                pending_rule = nil
              end
            else
              # Make sure we have a valid rule for multiport compression.
              #
              # Ignore if we're the last rule since this is only used for
              # pending rule optimization
              if (index != (existing_rules.count - 1)) &&
                 rule.to_s !~ /-p(rotocol)?\s+(ud|tc)p/ &&
                 rule.to_s !~ /--(d(estination-)?|s(ource-)?)ports?\s+/
              then
                pending_rule = rule
              else
                Puppet.debug("Adding: rule '#{rule}' to table '#{table}'")
                new_rules.append_rules(table, rule)

                pending_rule = nil
              end
            end
          end
        end

        return new_rules.prune_chains!
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

      private

      # Helpers to reduce redundancy

      def process_chain(chain)
        add_table(chain.table)
      end

      def process_rule(rule)
        add_chains(rule.table, rule.chain)
      end
    end
  end
end
