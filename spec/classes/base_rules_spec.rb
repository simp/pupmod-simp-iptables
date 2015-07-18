require 'spec_helper'

describe 'iptables::base_rules' do

  context  'on supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do
        context "iptables::base_rules class without any parameters" do
          let(:params) {{ }}
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_class('iptables::base_rules') }
          it { is_expected.to create_iptables_rule('global').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_lo').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('allow_v4_echo_request').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_all').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('drop_broadcast').with_apply_to('ipv4') }
          it { is_expected.to create_iptables_rule('drop_v6_broadcast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('drop_v4_multicast').with_apply_to('ipv4')}
          it { is_expected.to create_iptables_rule('drop_v6_multicast').with_apply_to('ipv6') }
          it { is_expected.to create_iptables_rule('established_related').with_apply_to('all') }
          it { is_expected.to create_iptables_rule('log_all').with_apply_to('all') }
        end
      end
    end
  end
end
