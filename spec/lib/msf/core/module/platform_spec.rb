require 'spec_helper'

RSpec.describe Msf::Module::Platform do

  context '.find_platform' do

    subject(:platform) do
      described_class.find_platform(plat_string)
    end

    describe 'Windows' do
      context '"win"' do
        let(:plat_string) { "win" }
        it { is_expected.to eq(Msf::Module::Platform::Windows) }
      end
    end

    describe 'Linux' do
      context '"linux"' do
        let(:plat_string) { "linux" }
        it { is_expected.to eq(Msf::Module::Platform::Linux) }
      end
    end

    describe 'OSX' do
      context '"osx"' do
        let(:plat_string) { "osx" }
        it { is_expected.to eq(Msf::Module::Platform::OSX) }
      end
    end

  end

end
