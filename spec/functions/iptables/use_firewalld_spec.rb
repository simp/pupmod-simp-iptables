#!/usr/bin/env ruby -S rspec
require 'spec_helper'

describe 'iptables::use_firewalld' do
  let(:facts) {{
    :simplib__firewalls => [
      'iptables',
      firewalld
    ],
    :os => {
      'name' => 'RedHat',
      'release' => {
        'major' => os_release
      }
    }
  }}

  ['8', '9'].each do |major|
    context "when EL#{major}" do
      let(:os_release) { major }
      let(:firewalld) { 'firewalld' }

      context 'when enable=true' do
        it { is_expected.to run.with_params(true).and_return(true) }
      end

      context 'when enable=false' do
        it { is_expected.to run.with_params(false).and_return(false) }
      end

      context 'when enable=firewalld' do
        it { is_expected.to run.with_params('firewalld').and_return(true) }
      end
    end
  end

  context 'when EL7' do
    let(:os_release) { '7' }
    let(:firewalld) { 'firewalld' }

    context 'when enable=true' do
      it { is_expected.to run.with_params(true).and_return(false) }
    end

    context 'when enable=false' do
      it { is_expected.to run.with_params(false).and_return(false) }
    end

    context 'when enable=firewalld' do
      it { is_expected.to run.with_params('firewalld').and_return(true) }
    end
  end

end
