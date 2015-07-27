require 'spec_helper'

describe 'iptables::prevent_localhost_spoofing' do
  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      let(:facts) do
        facts
      end

      context "on #{os}" do
        context "default spoofing prevention" do
          it { is_expected.to compile.with_all_deps }
          it { is_expected.to create_iptables_rule('prevent_ipv6_localhost_spoofing').with_apply_to('ipv6') }
        end
      end
    end
  end
end
