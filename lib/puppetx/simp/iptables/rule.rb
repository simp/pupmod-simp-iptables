module PuppetX
  module SIMP
    class IPTables::Rule

      attr_reader :rule
      attr_reader :rule_type
      attr_reader :table
      attr_reader :chain
      attr_reader :jump
      attr_reader :input_interface
      attr_reader :output_interface
      attr_reader :rule_hash

      # This is true if the rule has more than just a jump in it.
      attr_reader :complex

      def self.to_hash(rule)
        require 'optparse'
        require 'shellwords'


        opt_arr = Shellwords.shellwords(rule)

        opt_parser = OptionParser.new

        opts = Hash.new
        negate = false

        until opt_arr.empty? do
          begin
            opt_parser.parse!(opt_arr)
            opt_arr.shift
          rescue OptionParser::InvalidOption => e
            e.recover(opt_arr)

            key = opt_arr.shift.gsub(/^-*/,'')

            opts[key] ||= { :value => [], :negate => negate }

            while opt_arr.first && (opt_arr.first[0] != '-')
              opts[key][:value] << opt_arr.shift
            end

            if !opts[key][:value].empty? && (opts[key][:value].last.strip == '!')
              opts[key][:value].pop
              negate = true
            else
              negate = false
            end
          end
        end

        return opts
      end

      def self.parse(rule)
        output = {
          :chain => nil,
          :jump => nil,
          :input_interface => nil,
          :output_interface => nil
        }

        rule_hash = PuppetX::SIMP::IPTables::Rule.to_hash(rule)

        if rule_hash
          chain = rule_hash.find{ |k,_| ['A','D','I','R','N','P'].include?(k)}
          output[:chain] = chain.last[:value].first if chain

          jump = rule_hash.find{ |k,_| ['j'].include?(k)}
          output[:jump] = jump.last[:value].first if jump

          input_interface = rule_hash.find{ |k,_| ['i'].include?(k)}
          output[:input_interface] = input_interface.last[:value].first if input_interface

          output_interface = rule_hash.find{ |k,_| ['o'].include?(k)}
          output[:output_interface] = output_interface.last[:value].first if output_interface
        end

        output[:rule_hash] = rule_hash

        return output
      end

      # Create the particular rule. The containing table should be passed in
      # for future reference.
      def initialize(rule_str, table)
        @rule = rule_str.strip
        @rule_type = :rule

        if table.nil? or table.empty? then
          raise(Puppet::Error, "All rules must have an associated table: '#{rule}'")
        end

        @table = table.strip

        parsed_rule = PuppetX::SIMP::IPTables::Rule.parse(rule)

        @chain = parsed_rule[:chain]
        @jump = parsed_rule[:jump]
        @input_interface = parsed_rule[:input_interface]
        @output_interface = parsed_rule[:output_interface]
        @rule_hash = parsed_rule[:rule_hash]

        @complex = true

        if @rule == 'COMMIT' then
          @rule_type = :commit
        elsif @rule =~ /^\s*:(.*)\s+(.*)\s/
          @chain = $1
          @rule = ":#{@chain} #{$2} [0:0]"
          @rule_type = :chain
        end

        # If there is only a jump, then the rule is simple
        if (parsed_rule[:rule_hash].keys - ['A','D','I','R','N','P','j']).empty?
          @complex = false
        end
      end

      def to_s
        return @rule
      end
    end
  end
end
