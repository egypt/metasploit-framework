
describe Msf::Post::Unix::Priv do
  let(:mod) do
    mod = Msf::Post.new
    mod.extend described_class
    mod.instance_variable_set(:@session, session)

    mod
  end

  let(:session) do
    double("session", type: "meterpreter")
  end

  before do
    allow(mod).to receive(:cmd_exec).and_return(id_output)
  end

  describe '#is_root?' do
    subject do
      mod.is_root?
    end

    context 'id 1000' do
      let(:id_output) do
        "uid=1000(msfadmin) gid=1000(msfadmin) groups=1000(msfadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),107(lpadmin),124(sambashare),130(wireshark)"
      end

      it { is_expected.to be_falsey }
    end

    context 'id 0' do
      let(:id_output) do
        "uid=0(root) gid=0(root) groups=0(root)"
      end

      it { is_expected.to be_truthy }
    end
  end

end
