require 'spec_helper'

describe 'iptables' do

  it { should create_class('iptables') }
  it { should compile.with_all_deps }
end

