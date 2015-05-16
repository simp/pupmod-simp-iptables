module PuppetX
  module SIMP
    class IPTables::Rule

      attr_reader :rule
      attr_reader :rule_type
      attr_reader :table
      attr_reader :chain
      attr_reader :jump
      # This is true if the rule has more than just a jump in it.
      attr_reader :complex

      def self.parse(rule)
        output = {
          :chain => nil,
          :jump  => nil
        }

        if rule =~ /^\s*-(?:A|D|I|R|N|P)\s+(\S+)(?:.*-j\s+(.+)\s*)*/ then
          output[:chain] = $1
          output[:jump] = $2.to_s.split(/\s+/).first
        end

        return output
      end

      # Create the particular rule. The containing table should be passed in
      # for future reference.
      def initialize(rule,table)
        @rule = rule.strip
        @rule_type = :rule

        if table.nil? or table.empty? then
          raise(Puppet::Error,"All rules must have an associated table: '#{rule}'")
        end

        @table = table.strip

        parsed_rule = PuppetX::SIMP::IPTables::Rule.parse(rule)

        @chain = parsed_rule[:chain]
        @jump = parsed_rule[:jump]
        @complex = true

        if @rule == 'COMMIT' then
          @rule_type = :commit
        elsif @rule =~ /^\s*(:.*)\s+(.*)\s/ then
          @rule = "#{$1} #{$2} [0:0]"
          @rule_type = :chain
        end

        if @rule =~ /^\s*-(A|D|I|R|N|P)\s+\S+\s+-j\s+\S+\s*$/ then
          @complex = false
        end
      end

      def to_s
        return @rule
      end
    end
  end
end
