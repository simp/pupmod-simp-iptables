require 'spec_helper.rb'

# This covers the iptables::rule tests for the following:
#
#   * ALL rules
#   * IPSets
#   * Non-IPSets
#   * Rule/Family mismatches
#   * IPv4 and IPv6 working rules
#
# Protocol-specific tests are in the other test files in this directory.
#
describe "iptables::listen::all", :type => :define do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        let(:facts) do
          facts
        end

        let(:ipv4_nets) {
          [
            '10.0.2.0/24',
            '10.0.2.33/32',
            '1.2.3.4/32',
            '2.3.4.0/24',
            '3.0.0.0/8'
          ]
        }

        let(:ipv6_nets) {
          [
            'fe80::/64',
            '2001:cdba:0000:0000:0000:0000:3257:9652/128',
            '2001:cdba:0000:0000:0000:0000:3257:9652/16'
          ]
        }

        let(:hostnames) {
          [
            'foo.bar.baz',
            'i.like.cheese'
          ]
        }

        context 'firewalld mode' do
          let(:hieradata) { 'firewall__firewalld' }

          context "with hostnames in the address list" do
            let( :title  ){ 'hostnames' }

            let(:params){{
              :trusted_nets => ipv4_nets + hostnames + ipv6_nets
            }}

            it { is_expected.to compile.with_all_deps }
            it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
          end

          context "with '0.0.0.0/0' in the address list" do
            context 'all protocols' do
              let( :title  ){ 'allow_all' }

              let( :params ){{
                :trusted_nets => ipv4_nets + ['0.0.0.0/0']
              }}

              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end

            context 'IPv4 only' do
              let( :title  ){ 'allow_all_ipv4' }

              let(:params){{
                :trusted_nets => ipv4_nets + ['0.0.0.0/0'],
                :apply_to     => 'ipv4'
              }}

              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end

            context 'IPv6 only' do
              let( :title  ){ 'allow_all_ipv6' }

              let(:params){{
                :trusted_nets => ipv4_nets + ['::/0'],
                :apply_to     => 'ipv6'
              }}

              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end

            context 'IPv4 mismatched application' do
              let( :title  ){ 'ipv4 nets on ipv6' }

              let(:params){{
                :trusted_nets => ipv4_nets,
                :apply_to     => 'ipv6'
              }}

              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end

            context 'IPv6 mismatched application' do
              let( :title  ){ 'ipv6 nets on ipv4' }

              let(:params){{
                :trusted_nets => ipv6_nets,
                :apply_to     => 'ipv4'
              }}

              it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
            end
          end

          context "with trusted_nets in IPv4 CIDR format" do
            let( :title  ){ 'allow_all' }
            let( :params ){{
              :trusted_nets => ipv4_nets
            }}

            it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
          end

          context "with trusted_nets in IPv6 CIDR format" do
            let( :title  ){ 'allow_all' }
            let( :params ){{
              :trusted_nets => ipv6_nets,
              :apply_to    => 'ipv6'
            }}

            it { is_expected.to create_simp_firewalld__rule("all_#{title}") }
          end
        end
      end
    end
  end
end
