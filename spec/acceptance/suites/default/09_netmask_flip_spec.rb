require 'spec_helper_acceptance'

test_name 'iptables netmask flip'

hosts.each do |host|
  next unless host[:roles].include?('iptables')

  describe 'iptables::listen::tcp_stateful' do
    context 'precise matching' do
      context 'disabled' do
        let(:hieradata) { { 'iptables::precise_match' => false } }

        context 'origin' do
          let(:manifest) do
            <<~EOS
              class { 'iptables': }

              iptables::listen::tcp_stateful { 'allow_sshd':
                trusted_nets => ['0.0.0.0/0'],
                dports       => 22,
              }

              iptables_rule { 'tcp_test':
                table   => 'filter',
                comment => 'Test1',
                content => '-m state --state NEW -m tcp -p tcp -s 10.0.2.0/24 -m multiport --dports 1234 -j ACCEPT',
              }
            EOS
          end

          context 'prep' do
            it 'works without errors' do
              set_hieradata_on(host, hieradata)
              apply_manifest_on(host, manifest, catch_failures: true)
            end
          end

          context 'evaluation' do
            before(:all) do
              @iptables_save = on(host, 'iptables-save').output.lines
            end

            it 'has comment Test1' do
              expect(@iptables_save.grep(%r{Test1})).not_to be_empty
            end
          end
        end

        context 'updated comment' do
          let(:manifest) do
            <<~EOS
              class { 'iptables': }

              iptables::listen::tcp_stateful { 'allow_sshd':
                trusted_nets => ['0.0.0.0/0'],
                dports       => 22,
              }

              iptables_rule { 'tcp_test':
                table   => 'filter',
                comment => 'Test2',
                content => '-m state --state NEW -m tcp -p tcp -s 10.0.2.0/23 -m multiport --dports 1234 -j ACCEPT',
              }
            EOS
          end

          context 'prep' do
            it 'works without errors' do
              apply_manifest_on(host, manifest, catch_failures: true)
            end
          end

          context 'evaluation' do
            before(:all) do
              @iptables_save = on(host, 'iptables-save').output.lines
            end

            it 'does not have updated comment Test1' do
              expect(@iptables_save.grep(%r{Test1})).not_to be_empty
            end

            it 'has original netmask 24' do
              expect(@iptables_save.grep(%r{10.0.2.0/24})).not_to be_empty
            end

            it 'does not have comment Test2' do
              expect(@iptables_save.grep(%r{Test2})).to be_empty
            end

            it 'does not have updated netmask 23' do
              expect(@iptables_save.grep(%r{10.0.2.0/23})).to be_empty
            end
          end
        end
      end

      context 'enabled' do
        let(:hieradata) { { 'iptables::precise_match' => true } }

        context 'origin' do
          let(:manifest) do
            <<~EOS
              class { 'iptables': }

              iptables::listen::tcp_stateful { 'allow_sshd':
                trusted_nets => ['0.0.0.0/0'],
                dports       => 22,
              }

              iptables_rule { 'tcp_test':
                table   => 'filter',
                comment => 'Test3',
                content => '-m state --state NEW -m tcp -p tcp -s 10.0.2.0/24 -m multiport --dports 1234 -j ACCEPT',
              }
            EOS
          end

          context 'prep' do
            it 'works without errors' do
              set_hieradata_on(host, hieradata)
              apply_manifest_on(host, manifest, catch_failures: true)
            end
          end

          context 'evaluation' do
            before(:all) do
              @iptables_save = on(host, 'iptables-save').output.lines
            end

            it 'has comment Test3' do
              expect(@iptables_save.grep(%r{Test3})).not_to be_empty
            end
          end
        end

        context 'updated comment' do
          let(:manifest) do
            <<~EOS
              class { 'iptables': }

              iptables::listen::tcp_stateful { 'allow_sshd':
                trusted_nets => ['0.0.0.0/0'],
                dports       => 22,
              }

              iptables_rule { 'tcp_test':
                table   => 'filter',
                comment => 'Test4',
                content => '-m state --state NEW -m tcp -p tcp -s 10.0.2.0/23 -m multiport --dports 1234 -j ACCEPT',
              }
            EOS
          end

          context 'prep' do
            it 'works without errors' do
              apply_manifest_on(host, manifest, catch_failures: true)
            end
          end

          context 'evaluation' do
            before(:all) do
              @iptables_save = on(host, 'iptables-save').output.lines
            end

            it 'has updated comment Test3' do
              expect(@iptables_save.grep(%r{Test4})).not_to be_empty
              expect(@iptables_save.grep(%r{Test3})).to be_empty
            end

            it 'has updated netmask /23' do
              expect(@iptables_save.grep(%r{10.0.2.0/23})).not_to be_empty
              expect(@iptables_save.grep(%r{10.0.2.0/24})).to be_empty
            end
          end
        end
      end
    end
  end
end
