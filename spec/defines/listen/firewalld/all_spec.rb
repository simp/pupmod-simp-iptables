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
            it { is_expected.to create_notify('iptables::firewalld::rule - hostname warning').with(
                {
                  :message => /foo\.bar\.baz, i\.like\.cheese/,
                  :withpath => true,
                  :loglevel => 'warning'
                }
              )
            }
          end

          context "with '0.0.0.0/0' in the address list" do
            context 'all protocols' do
              let( :title  ){ 'allow_all' }

              let( :params ){{
                :trusted_nets => ipv4_nets + ['0.0.0.0/0']
              }}
              it { is_expected.to create_iptables__listen__all(title) }

              it { is_expected.not_to create_firewalld__custom_service("simp_all_#{title}") }
              it { is_expected.not_to create_firewalld_service("simp_all_#{title}") }
              it { is_expected.not_to create_firewalld_ipset('simp-YBi8gcbxcIq0JuB3tmmajXBuPA') }
              it { is_expected.not_to create_firewalld_ipset('simp-Z4NZ2BaANQcFilLyb0EOS098rm') }
              it {
                is_expected.to create_firewalld_rich_rule("simp_11_all_#{title}_simp-YBi8gcbxcIq0JuB3tmmajXBuPA").with(
                  {
                    :ensure  => 'present',
                    :family  => 'ipv4',
                    :source  => '0.0.0.0/0',
                    :service => nil,
                    :action  => 'accept',
                    :zone    => '99_simp',
                    :require => 'Service[firewalld]'
                  }
                )
              }
              it {
                is_expected.to create_firewalld_rich_rule("simp_11_all_#{title}_simp-Z4NZ2BaANQcFilLyb0EOS098rm").with(
                  {
                    :ensure  => 'present',
                    :family  => 'ipv6',
                    :source  => '::/0',
                    :service => nil,
                    :action  => 'accept',
                    :zone    => '99_simp',
                    :require => 'Service[firewalld]'
                  }
                )
              }
            end

            context 'IPv4 only' do
              let( :title  ){ 'allow_all_ipv4' }

              let(:params){{
                :trusted_nets => ipv4_nets + ['0.0.0.0/0'],
                :apply_to     => 'ipv4'
              }}

              it {
                is_expected.to create_firewalld_rich_rule("simp_11_all_#{title}_simp-YBi8gcbxcIq0JuB3tmmajXBuPA").with(
                  {
                    :ensure  => 'present',
                    :family  => 'ipv4',
                    :source  => '0.0.0.0/0',
                    :service => nil,
                    :action  => 'accept',
                    :zone    => '99_simp',
                    :require => 'Service[firewalld]'
                  }
                )
              }

              it { is_expected.not_to create_firewalld_rich_rule("simp_11_all_#{title}_simp-Z4NZ2BaANQcFilLyb0EOS098rm") }
            end

            context 'IPv6 only' do
              let( :title  ){ 'allow_all_ipv6' }

              let(:params){{
                :trusted_nets => ipv4_nets + ['::/0'],
                :apply_to     => 'ipv6'
              }}

              it {
                is_expected.not_to create_firewalld_rich_rule("simp_11_all_#{title}_simp-Z4NZ2BaANQcFilLyb0EOS098rm").with(
                  {
                    :ensure  => 'present',
                    :family  => 'ipv6',
                    :source  => '[::]/0',
                    :service => nil,
                    :action  => 'accept',
                    :zone    => 'simp',
                    :require => 'Service[firewalld]'
                  }
                )
              }

              it { is_expected.not_to create_firewalld_rich_rule("simp_11_all_#{title}_simp-YBi8gcbxcIq0JuB3tmmajXBuPA") }
            end

            context 'IPv4 mismatched application' do
              let( :title  ){ 'ipv4 nets on ipv6' }

              let(:params){{
                :trusted_nets => ipv4_nets,
                :apply_to     => 'ipv6'
              }}

              it 'has no rich rules created' do
                expect(catalogue.resources.select{|r| r.type == 'Firewalld_rich_rule'}).to eq([])
              end
            end

            context 'IPv6 mismatched application' do
              let( :title  ){ 'ipv6 nets on ipv4' }

              let(:params){{
                :trusted_nets => ipv6_nets,
                :apply_to     => 'ipv4'
              }}

              it 'has no rich rules created' do
                expect(catalogue.resources.select{|r| r.type == 'Firewalld_rich_rule'}).to eq([])
              end
            end
          end

          context "with trusted_nets in IPv4 CIDR format" do
            let( :title  ){ 'allow_all' }
            let( :params ){{
              :trusted_nets => ipv4_nets
            }}

            it { is_expected.to create_iptables__listen__all(title) }
            it { is_expected.not_to create_firewalld__custom_service("simp_#{title}") }
          end

          context "with trusted_nets in IPv6 CIDR format" do
            let( :title  ){ 'allow_all' }
            let( :params ){{
              :trusted_nets => ipv6_nets,
              :apply_to    => 'ipv6'
            }}
            it { is_expected.to create_iptables__listen__all(title) }
            it { is_expected.not_to create_iptables_rule("all_#{title}") }
          end
        end
      end
    end
  end
end
