# Split a stringified Iptables::DestPort into an Array that contain groupings
# of `max_length` size.
Puppet::Functions.create_function(:'iptables::slice_ports') do
  # @param input One or more ports or port ranges, all represented
  #   as strings.
  #
  # @param max_length The maximum length of each group.
  #
  # @return [Array[Array[String]]]]
  dispatch :slice_ports do
    required_param 'Variant[String,Array[String]]', :input
    required_param 'Integer[1]',                    :max_length
  end

  def slice_ports(input, max_length)
    to_slice = Array(input).flatten
    split_char = ':'

    if max_length == 1 && to_slice.any? { |entry| entry.include?(split_char) }
      err_msg = 'iptables::slice_port: max_length must be >=2 when input has a port range'
      raise(err_msg)
    end

    retval = []
    count = 0
    group = []
    to_slice.each do |entry|
      num_values = entry.include?(split_char) ? 2 : 1
      if count + num_values <= max_length
        count += num_values
        group << entry
      else
        retval << group
        count = num_values
        group = [ entry ]
      end
    end
    retval << group unless group.empty?

    retval
  end
end
