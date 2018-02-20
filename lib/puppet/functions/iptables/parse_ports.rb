# Convert a hash with a user friendly format to a hash that can be consumed to
#   create Puppet resources
#
# @param ports_hash
#   A hash with structure as defined below that will open ports based on the
#   structure of the hash.
#   @example An example section of hieradata:
#     iptables::ports:
#       defaults:
#         apply_to: ipv4
#       80:
#       53:
#         proto: udp
#       443:
#         apply_to: ipv6
#       514:
#         proto: [udp,tcp]
#
Puppet::Functions.create_function(:'iptables::parse_ports') do
  dispatch :parse do
    required_param 'Hash', :ports_hash
  end

  def parse(ports_hash)
    # ports_hash comes in frozen, so you can't modify it
    ports_hash_dup = ports_hash.dup

    # extract defaults key and remove it from iteration
    defaults = ports_hash_dup.delete('defaults') || {}
    ports    = {}

    # go through and find all possible permutations of ports and protocols
    ports_hash_dup.each do |port,options|
      if options.is_a? Hash
        # same deal with options
        options_dup = options.dup
        proto = options_dup['proto'] || defaults['proto'] || 'tcp'
        options_dup.delete('proto')
      elsif options == 'nil' or options.nil?
        proto = defaults['proto'] || 'tcp'
        options_dup = {}
      end
      # ... and defaults
      defaults_dup = defaults.dup
      defaults_dup.delete('proto')

      Array(proto).each do |po|
        args = defaults_dup.to_h.merge(options_dup)
        ports["port_#{port}_#{po}"] = { 'dports' => [port.to_i] }.merge(args)
      end
    end
    ports
  end
end
