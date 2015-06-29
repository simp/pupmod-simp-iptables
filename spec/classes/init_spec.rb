require 'spec_helper'

describe 'iptables' do
  shared_examples_for "a structured module" do
    it { should create_class('iptables') }
    it { should compile.with_all_deps }
  end


  context  'supported operating systems' do
    on_supported_os.each do |os, facts|
      context "on #{os}" do
        context "iptables class without any parameters" do
          let(:params) {{ }}
          it_behaves_like "a structured module"
        end

        context "iptables class with firewall disabled" do
          let(:params) {{
            :disable => true,
          }}
          it_behaves_like "a structured module"
        end
      end
    end
  end
end
