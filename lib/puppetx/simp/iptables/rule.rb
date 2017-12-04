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
            value = []

            opts[key] ||= { :value => nil, :negate => negate }

            while opt_arr.first && (opt_arr.first[0] != '-')
              value << opt_arr.shift
            end

            if !value.empty? && (value.last.strip == '!')
              value.pop
              negate = true
            else
              negate = false
            end

            opts[key][:value] = value.join(' ')
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
          output[:chain] = chain.last[:value] if chain

          jump = rule_hash.find{ |k,_| ['j'].include?(k)}
          output[:jump] = jump.last[:value] if jump

          input_interface = rule_hash.find{ |k,_| ['i'].include?(k)}
          output[:input_interface] = input_interface.last[:value] if input_interface

          output_interface = rule_hash.find{ |k,_| ['o'].include?(k)}
          output[:output_interface] = output_interface.last[:value] if output_interface
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

      def normalize_addresses(to_normalize)
        require 'ipaddr'

        normalized_array = []

        Array(to_normalize).each do |item|
          begin
            normalized_array << IPAddr.new(item)
          rescue ArgumentError, NoMethodError, IPAddr::InvalidAddressError
            normalized_array << item
          end
        end

        return normalized_array
      end

      def ==(other_rule)
        return false if (other_rule.nil? || other_rule.rule_hash.nil? || other_rule.rule_hash.empty?)

        return false if (@rule_hash.size != other_rule.rule_hash.size)

        local_hash = @rule_hash.dup
        other_hash = other_rule.rule_hash.dup

        local_hash.each_key do |key|
          local_hash[key][:value] = normalize_addresses(local_hash[key][:value]) if (other_hash[key] && other_hash[key][:value])
        end

        other_hash.each_key do |key|
          other_hash[key][:value] = normalize_addresses(other_hash[key][:value]) if (other_hash[key] && other_hash[key][:value])
        end

        return local_hash == other_hash
      end
    end
  end
end
