Puppet::Type.type(:xt_recent).provide(:set) do
  confine :kernel => 'Linux'
  confine :true => ( Facter[:kernelmajversion].value.to_f >= 2.6 )
  commands :modprobe => '/sbin/modprobe'

  def initialize(*args)
    super(*args)

    if not File.exist?(resource[:name]) then
      modprobe "xt_recent"
    end

    # All of our little friends need to be writable
    Dir.glob("#{resource[:name]}/*").each do |file|
      File.chmod(0600,file) unless File.writable?(file)
    end
  end

  def ip_list_tot
    File.read("#{resource[:name]}/#{__method__}").chomp
  end

  def ip_list_tot=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_pkt_list_tot
    File.read("#{resource[:name]}/#{__method__}").chomp
  end

  def ip_pkt_list_tot=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_list_hash_size
    # If this is 0, then it's getting auto-calculated and we shouldn't
    # check it.
    if resource[__method__].to_s == '0' then
      return resource[__method__]
    else
      File.read("#{resource[:name]}/#{__method__}").chomp
    end
  end

  def ip_list_hash_size=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_list_perms
    File.read("#{resource[:name]}/#{__method__}").chomp
  end

  def ip_list_perms=(should)
    # Have to un-munge the field here.
    should = should.to_i(10).to_s(8)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_list_uid
    File.read("#{resource[:name]}/#{__method__}").chomp
  end

  def ip_list_uid=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_list_gid
    File.read("#{resource[:name]}/#{__method__}").chomp
  end

  def ip_list_gid=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end
end
