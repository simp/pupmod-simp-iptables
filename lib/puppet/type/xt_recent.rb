Puppet::Type.newtype(:xt_recent) do
  @doc =<<-EOM
    Sets the various options on the running xt_recent kernel module.

    If the module needs to be loaded, attempts to load the module.
  EOM

  newparam(:name) do
    isnamevar
    desc "The path to the xt_recent variables to be manipulated"

    validate do |value|
      require 'pathname'

      if not Pathname.new(value).absolute? then
        fail Puppet::Error, "'name' must be an absolute path, got: '#{value}'"
      end
    end
  end

  newproperty(:ip_list_tot) do
    desc <<-EOM
      The number of addresses remembered per table. This effectively
      becomes the maximum size of your block list. Be aware that
      more addresses means more load on your system.
    EOM

    newvalues(/^\d+$/)
    defaultto '100'
  end

  newproperty(:ip_pkt_list_tot) do
    desc <<-EOM
      The number of packets per address remembered.
    EOM

    newvalues(/^\d+$/)
    defaultto '20'
  end

  newproperty(:ip_list_hash_size) do
    desc <<-EOM
      Hash table size. 0 means to calculate it based on ip_list_tot.
    EOM

    newvalues(/^\d+$/)
    defaultto '0'
  end

  newproperty(:ip_list_perms) do
    desc <<-EOM
      Permissions for /proc/net/xt_recent/* files.
    EOM

    newvalues(/^[0-7]{4}$/)
    defaultto '0640'
  end

  newproperty(:ip_list_uid) do
    desc <<-EOM
      Numerical UID for ownership of /proc/net/xt_recent/* files.
    EOM

    newvalues(/^\d+$/)
    defaultto '0'
  end

  newproperty(:ip_list_gid) do
    desc <<-EOM
      Numerical GID for ownership of /proc/net/xt_recent/* files.
    EOM

    newvalues(/^\d+$/)
    defaultto '0'
  end

  autorequire(:file) do
    [ '/etc/modprobe.d/xt_recent.conf' ]
  end
end
