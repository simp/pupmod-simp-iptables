# @param ports
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
    # extract defaults key and remove it from iteration
    defaults = ports_hash.delete('defaults') || {}
    ports    = {}

    # go through and find all possible permutations of ports and protocols
    ports_hash.each do |port,options|
      if options.is_a? Hash
        proto = options['proto'] || defaults['proto'] || 'tcp'
        options.delete('proto')
      elsif options == 'nil'
        proto = defaults['proto'] || 'tcp'
        options = {}
      end
      defaults.delete('proto')

      Array(proto).each do |po|
        args = defaults.merge(options)
        ports["port_#{port}_#{po}"] = { 'dports' => [port.to_i] }.merge(args)
      end
    end
    ports
  end
end
