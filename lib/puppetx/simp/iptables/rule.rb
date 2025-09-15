#
class PuppetX::SIMP::IPTables::Rule
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

  def self.normalize_addresses(to_normalize)
    require 'ipaddr'

    normalized_array = []

    Array(to_normalize).each do |item|
      # Short circuit if it's obviously not an IP address
      if (item.count('.') == 3) || (item.count(':') > 1)
        begin
          test_addr = IPAddr.new(item)

          # Grab the netmask from the string and assign a reasonable default
          # if one does not exist
          test_netmask = item.split('/')[1] || ((test_addr.family == 2) ? '32' : '128')

          normalized_array << "#{test_addr}/#{test_netmask}"
        # rubocop:disable Lint/ShadowedException
        rescue ArgumentError, NoMethodError, IPAddr::InvalidAddressError
          normalized_array << item
        end
        # rubocop:enable Lint/ShadowedException
      else
        normalized_array << item
      end
    end

    return normalized_array.first if normalized_array.size == 1
    normalized_array
  end

  def self.to_hash(rule)
    require 'optparse'
    require 'shellwords'

    opt_arr = Shellwords.shellwords(rule)

    opt_parser = OptionParser.new

    opts = {}
    negate = false

    until opt_arr.empty?
      begin
        opt_parser.parse!(opt_arr)
        opt_arr.shift
      rescue OptionParser::InvalidOption => e
        e.recover(opt_arr)

        key = opt_arr.shift.gsub(%r{^-*}, '')
        value = []

        value << opt_arr.shift while opt_arr.first && (opt_arr.first[0] != '-')

        negate_next = false
        if !value.empty? && (value.last.strip == '!')
          value.pop
          negate_next = true
        end

        next if !negate && ((value == ['0.0.0.0/0']) || (value == ['::/0']))

        opts[key] ||= { value: nil, negate: negate }
        opts[key][:value] = value.join(' ')
        opts[key][:value] = opts[key][:value].split(',').sort if opts[key][:value].include?(',')
        opts[key][:value] = normalize_addresses(opts[key][:value])

        negate = negate_next
      end
    end

    opts
  end

  def self.parse(rule)
    output = {
      chain: nil,
      jump: nil,
      input_interface: nil,
      output_interface: nil,
    }

    rule_hash = PuppetX::SIMP::IPTables::Rule.to_hash(rule)

    if rule_hash
      chain = rule_hash.find { |k, _| ['A', 'D', 'I', 'R', 'N', 'P'].include?(k) }
      output[:chain] = chain.last[:value] if chain

      jump = rule_hash.find { |k, _| ['j'].include?(k) }
      output[:jump] = jump.last[:value] if jump

      input_interface = rule_hash.find { |k, _| ['i'].include?(k) }
      output[:input_interface] = input_interface.last[:value] if input_interface

      output_interface = rule_hash.find { |k, _| ['o'].include?(k) }
      output[:output_interface] = output_interface.last[:value] if output_interface
    end

    output[:rule_hash] = rule_hash

    output
  end

  # Create the particular rule. The containing table should be passed in
  # for future reference.
  def initialize(rule_str, table)
    @rule = rule_str.strip
    @rule_type = :rule

    if table.nil? || table.empty?
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

    if @rule == 'COMMIT'
      @rule_type = :commit
    elsif @rule =~ %r{^\s*:(.*)\s+(.*)\s}
      @chain = ::Regexp.last_match(1)
      @rule = ":#{@chain} #{::Regexp.last_match(2)} [0:0]"
      @rule_type = :chain
    end

    # If there is only a jump, then the rule is simple
    return unless (parsed_rule[:rule_hash].keys - ['A', 'D', 'I', 'R', 'N', 'P', 'j']).empty?
    @complex = false
  end

  def to_s
    @rule
  end

  # Retained for backward compatibiilty
  def normalize_addresses(to_normalize)
    self.class.normalize_addresses(to_normalize)
  end

  def ==(other)
    return false if other.nil? || other.rule_hash.nil? || other.rule_hash.empty?

    return true if rule.strip == other.to_s.strip

    return false if @rule_hash.size != other.rule_hash.size

    local_hash = Marshal.load(Marshal.dump(@rule_hash))
    other_hash = Marshal.load(Marshal.dump(other.rule_hash))

    local_hash == other_hash
  end
end
