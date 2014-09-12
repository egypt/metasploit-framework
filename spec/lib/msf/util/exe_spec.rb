# -*- coding:binary -*-

require 'msf/core'
require 'msf/base/simple'
require 'spec_helper'

require 'support/shared/contexts/msf/util/exe'

describe Msf::Util::EXE do

  subject do
    described_class
  end

  describe '.encode_stub' do
    context "with a UNIX command payload" do
      let(:framework) do
        Msf::Simple::Framework.create(
          :module_types => [ Msf::MODULE_ENCODER ],
          'DisableDatabase' => true
        )
      end
      # Just a collection of typically bad characters so we force encoding
      # to happen
      let(:stuff) { %q%$(){} \\|% }

      def try(badchars)
        echo_stuff = %Q|echo '#{stuff}'|
        encoded = subject.encode_stub(framework, [ ARCH_CMD ], echo_stuff, Msf::Module::PlatformList.transform('unix'), badchars)
        encoded.should be_a(String)
        output = `#{encoded}`.chomp

        output
      end

      # Must always have one of $ or space

      it "should produce a functional command when badchars is empty" do
        try(%q^^).should eq(stuff)
      end

      it "should produce a functional command with no spaces" do
        try(%q^ ^).should eq(stuff)
      end

      it "should produce a functional command with no pipes" do
        pending "wtf, single quotes" do
          try(%q^|^).should eq(stuff)
        end
      end
      it "should produce a functional command with no pipes, or backticks" do
        pending "wtf, single quotes" do
          try(%q^|`^).should eq(stuff)
        end
      end
      it "should produce a functional command with no pipes, backticks, or dollars" do
        try(%q^|`$^).should eq(stuff)
      end

      it "should produce a functional command with no pipes, backticks, or spaces" do
        pending "wtf, single quotes" do
          try(%q^|` ^).should eq(stuff)
        end
      end

      it "should produce a functional command with no whacks" do
        # Rule out echo -ne altogether
        try(%q^\\^).should eq(stuff)
      end

      it "should produce a functional command with no whacks, or ticks" do
        # Backslash rules out echo, so now we're exercising perl
        try(%q^\\'^).should eq(stuff)
      end
      it "should produce a functional command with no whacks, or spaces" do
        try(%q^\\ ^).should eq(stuff)
      end
      it "should produce a functional command with no whacks, ticks, or spaces" do
        try(%q^\\' ^).should eq(stuff)
      end
    end
  end

  $framework = Msf::Simple::Framework.create(
    :module_types => [ Msf::MODULE_NOP ],
    'DisableDatabase' => true
  )

  describe '.win32_rwx_exec' do
    it "should contain the shellcode" do
      bin = subject.win32_rwx_exec("asdfjklASDFJKL")
      bin.should include("asdfjklASDFJKL")
    end
  end

  describe '.to_executable_fmt' do
    it "should output nil when given a bogus format" do
      bin = subject.to_executable_fmt($framework, "", "", "", "does not exist", {})

      bin.should == nil
    end

    include_context 'Msf::Util::Exe'

    @platform_format_map.each do |plat, formats|
      context "with platform=#{plat}" do
        let(:platform) do
          Msf::Module::PlatformList.transform(plat)
        end

        it "should output nil when given bogus format" do
          bin = subject.to_executable_fmt($framework, formats.first[:arch], platform, "\xcc", "asdf", {})
          bin.should == nil
        end
        it "should output nil when given bogus arch" do
          bin = subject.to_executable_fmt($framework, "asdf", platform, "\xcc", formats.first[:format], {})
          bin.should == nil
        end
        [ ARCH_X86, ARCH_X64, ARCH_X86_64, ARCH_PPC, ARCH_MIPSLE, ARCH_MIPSBE, ARCH_ARMLE ].each do |arch|
          it "returns nil when given bogus format for arch=#{arch}" do
            bin = subject.to_executable_fmt($framework, arch, platform, "\xcc", "asdf", {})
          end
        end

        formats.each do |format_hash|
          fmt   = format_hash[:format]
          arch  = format_hash[:arch]

          if format_hash[:skip]
            skip "returns an executable when given arch=#{arch}, fmt=#{fmt}"
            next
          end

          it "returns an executable when given arch=#{arch}, fmt=#{fmt}" do
            bin = subject.to_executable_fmt($framework, arch, platform, "\xcc", fmt, {})
            bin.should be_a String

            verify_bin_fingerprint(format_hash, bin)
          end

        end

      end
    end

  end

end

