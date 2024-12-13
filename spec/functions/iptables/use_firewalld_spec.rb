#!/usr/bin/env ruby -S rspec
require 'spec_helper'

describe 'iptables::use_firewalld' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'simplib__firewalls' => [
            'iptables',
            'firewalld',
          ],
        )
      end

      context 'when enable=true' do
        it do
          if Puppet[:strict] == :error
            is_expected.to run.with_params(true).and_raise_error(%r{iptables::use_firewalld is deprecated})
          else
            is_expected.to run.with_params(true).and_return((facts[:os][:name] == 'Amazon' && facts[:os][:release][:major] == '2') ? false : true)
          end
        end
      end

      context 'when enable=false' do
        it do
          if Puppet[:strict] == :error
            is_expected.to run.with_params(false).and_raise_error(%r{iptables::use_firewalld is deprecated})
          else
            is_expected.to run.with_params(false).and_return(false)
          end
        end
      end

      context 'when enable=firewalld' do
        it do
          if Puppet[:strict] == :error
            is_expected.to run.with_params('firewalld').and_raise_error(%r{iptables::use_firewalld is deprecated})
          else
            is_expected.to run.with_params('firewalld').and_return(true)
          end
        end
      end
    end
  end
end
