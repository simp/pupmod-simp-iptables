# An ``iptables_rule`` compatible port range or Array
type Iptables::DestPort = Variant[Simplib::Port, Iptables::PortRange, Array[Variant[Simplib::Port, Iptables::PortRange]]]
