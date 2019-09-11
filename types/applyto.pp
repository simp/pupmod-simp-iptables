# Valid families to which rules should apply
type Iptables::ApplyTo = Enum[
  'ipv4',
  'ipv6',
  'all',
  'auto'
]
