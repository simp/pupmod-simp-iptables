#!/usr/bin/env ruby -S rspec
require 'spec_helper'

describe 'iptables::slice_ports' do
  context 'when single port' do
    let(:input) { '0' }
    it 'should return a single array with input' do
      is_expected.to run.with_params(input, 15).and_return([[input]])
    end
  end

  context 'when array of single ports' do
    let(:input) { ['1', '2', '3', '4', '5', '6'] }

    context 'when max_length is < input array size' do
      it 'should return multiple sub-arrays' do
        expected = [['1','2','3','4'], ['5','6']]
        is_expected.to run.with_params(input, 4).and_return(expected)
      end
    end

    context 'when max_length is >= input array size' do
      it 'should return one sub-array' do
        is_expected.to run.with_params(input, input.size).and_return([input])
      end
    end
  end

  context 'when single range' do
    let(:input) { '59:300' }

    it 'should return one sub-array if max_length >= 2' do
      is_expected.to run.with_params(input, 2).and_return([[input]])
    end
  end

  context 'when array of ranges' do
    let(:input) { ['10:20', '110:120', '210:220'] }

    it 'should treat each range as 2 entries' do
      expected = [['10:20'], ['110:120'], ['210:220']]
      is_expected.to run.with_params(input, 2).and_return(expected)

      expected = [['10:20','110:120'], ['210:220']]
      is_expected.to run.with_params(input, 4).and_return(expected)
    end

    it 'should not split any range into sub-arrays' do
      expected = [['10:20'], ['110:120'], ['210:220']]
      is_expected.to run.with_params(input, 3).and_return(expected)
    end
  end

  context 'when mixed array of individual ports and ranges ' do
    let(:input) { ['1', '2', '3:10', '14', '15', '20:120' ] }

    it 'should treat each range a 2 entries' do
      expected = [['1', '2','3:10'], ['14', '15', '20:120']]
      is_expected.to run.with_params(input, 4).and_return(expected)
    end

    it 'should not split any range into sub-arrays' do
      expected = [['1', '2'], ['3:10', '14'], ['15', '20:120']]
      is_expected.to run.with_params(input, 3).and_return(expected)
    end
  end

  context 'failures' do
    let(:input) { '59:300' }

    it 'should fail if max_length is 1 and input contains a port range' do
      # Where this function is used, max_length = 15, so not going
      # to worry about fixing this edge case for now.
      is_expected.to run.with_params(input, 1).and_raise_error(/max_length must be >=2 when input has a port range/)
    end
  end

end
