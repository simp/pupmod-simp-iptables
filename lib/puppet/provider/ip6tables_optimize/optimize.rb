require File.join(File.dirname(__FILE__), '..', 'iptables_optimize', 'optimize')
Puppet::Type.type(:ip6tables_optimize).provide(:optimize, :parent => Puppet::Type::Iptables_optimize::ProviderOptimize) do
  desc <<-EOM
    Run through all of the proposed IP6Tables rules and optimize them where
    possible.

    Provides a fail-safe mode to just open port 22 in the case that the rules
    fail to apply.

    Builds off of the ``iptables_optimize`` provider.
  EOM

  commands :ip6tables_save => 'ip6tables-save'

  has_feature :ipv6

  def initialize(*args)
    super(*args)

    # Set up some reasonable defaults in the case of an epic fail.
    @ipt_config[:id] = 'ip6tables'
    @ipt_config[:enabled] = !Facter.value('ipaddress6').nil?,
    @ipt_config[:default_config].gsub!('icmp-type','icmpv6-type')
  end

  private

  def self.iptables_save
    %x{#{command(:ip6tables_save)}}
  end
end
