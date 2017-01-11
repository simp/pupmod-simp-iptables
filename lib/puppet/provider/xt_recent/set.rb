Puppet::Type.type(:xt_recent).provide(:set) do
  desc <<-EOM
    Set parameters on the xt_recent kernel module and ensure that the module is
    loaded.
  EOM

  confine :kernel => 'Linux'
  confine :true => ( Facter.value('kernelmajversion').to_f >= 2.6 )
  commands :modprobe => '/sbin/modprobe'

  def initialize(*args)
    super(*args)

    unless File.exist?(resource[:name])
      modprobe "xt_recent"
    end

    # All parameter files need to be writable
    Dir.glob("#{resource[:name]}/*").each do |file|
      # can't use File.writeable? as it always returns true for root
      File.chmod(0600,file) unless ((File.stat(file).mode & 0200) != 0)
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
    if resource[__method__].to_s == '0'
      return resource[__method__]
    else
      File.read("#{resource[:name]}/#{__method__}").chomp
    end
  end

  def ip_list_hash_size=(should)
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should }
  end

  def ip_list_perms
    # Have to convert back to octal here, so the comparison of the decimal value
    # stored in the file with the octal string configured via parameters makes sense.
    sprintf("%#o",File.read("#{resource[:name]}/#{__method__}").chomp.to_i)
  end

  def ip_list_perms=(should)
    # Can't use munge in xt_recent type, as screws up comparison when checking for
    # changes in resource catalog.  So, convert from octal string to decimal string here.
    File.open("#{resource[:name]}/#{__method__.to_s.chop}",'w'){|fh| fh.puts should.to_i(8).to_s(10) }
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
