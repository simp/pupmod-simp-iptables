require File.join(File.dirname(__FILE__), '..', 'iptables_optimize', 'optimize')
Puppet::Type.type(:ip6tables_optimize).provide(:optimize, :parent => Puppet::Type::Iptables_optimize::ProviderOptimize) do
  commands :ip6tables => 'ip6tables'
  commands :ip6tables_restore => 'ip6tables-restore'
  commands :ip6tables_save => 'ip6tables-save'

  def initialize(*args)
    super(*args)

    # Set up some reasonable defaults in the case of an epic fail.
    @ipt_config[:id] = 'ip6tables'
    @ipt_config[:enabled] = !Facter.value('ipaddress6').nil?,
    @ipt_config[:default_config].gsub!('icmp-type','icmpv6-type')
  end

  private

  def self.iptables(args)
    %x{#{command(:ip6tables)} #{args}}
  end

  def self.iptables_restore(args)
    %x{#{command(:ip6tables_restore)} #{args}}
  end

  def self.iptables_save
    %x{#{command(:ip6tables_save)}}
  end
end
