
require 'msf/core/post/unix'

describe Msf::Post::Unix do
  let(:mod) do
    mod = Msf::Post.new
    mod.extend described_class
    mod.instance_variable_set(:@session, session)

    mod
  end

  subject { mod }

  let(:session) do
    double("session", type: "meterpreter")
  end

  let(:passwd) do
    %q{
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/bin/sh
    bin:x:2:2:bin:/bin:/bin/sh
    sys:x:3:3:sys:/dev:/bin/sh
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/bin/sh
    man:x:6:12:man:/var/cache/man:/bin/sh
    lp:x:7:7:lp:/var/spool/lpd:/bin/sh
    mail:x:8:8:mail:/var/mail:/bin/sh
    news:x:9:9:news:/var/spool/news:/bin/sh
    uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
    proxy:x:13:13:proxy:/bin:/bin/sh
    www-data:x:33:33:www-data:/var/www:/bin/sh
    backup:x:34:34:backup:/var/backups:/bin/sh
    list:x:38:38:Mailing List Manager:/var/list:/bin/sh
    irc:x:39:39:ircd:/var/run/ircd:/bin/sh
    gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
    nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
    libuuid:x:100:101::/var/lib/libuuid:/bin/sh
    dhcp:x:101:102::/nonexistent:/bin/false
    syslog:x:102:103::/home/syslog:/bin/false
    klog:x:103:104::/home/klog:/bin/false
    sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
    msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
    bind:x:105:113::/var/cache/bind:/bin/false
    postfix:x:106:115::/var/spool/postfix:/bin/false
    ftp:x:107:65534::/home/ftp:/bin/false
    postgres:x:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
    mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
    tomcat55:x:110:65534::/usr/share/tomcat5.5:/bin/false
    distccd:x:111:65534::/:/bin/false
    user:x:1001:1001:just a user,111,,:/home/user:/bin/bash
    service:x:1002:1002:,,,:/home/service:/bin/bash
    telnetd:x:112:120::/nonexistent:/bin/false
    proftpd:x:113:65534::/var/run/proftpd:/bin/false
    statd:x:114:65534::/var/lib/nfs:/bin/false
    snmp:x:115:65534::/var/lib/snmp:/bin/false
    }.gsub(/^\s*/, '').strip
  end

  describe '#getent_passwd' do
    subject(:getent_passwd) do
      mod.getent_passwd
    end

    context 'with a working getent' do
      before do
        allow(mod).to receive(:cmd_exec).with("getent passwd").and_return(passwd)
      end
      it { is_expected.to eq(passwd) }
    end

    context 'with a busted getent' do
      before do
        allow(mod).to receive(:cmd_exec).with("getent passwd").and_return("")
        allow(mod).to receive(:file_exist?).with("/etc/passwd").and_return(true)
        allow(mod).to receive(:read_file).with("/etc/passwd").and_return(passwd)
      end
      it { is_expected.to eq(passwd) }
    end
  end

  describe '#get_users' do
    subject(:get_users) do
      mod.get_users
    end

    before do
      allow(mod).to receive(:getent_passwd).and_return(passwd)
    end

    specify do
      expect(get_users.size).to eq(passwd.lines.size)
    end
    specify do
      all_names = Set.new(get_users.map { |u| u[:name] })
      expected_users = Set.new(passwd.lines.map { |line| line.split(':').first })
      expect(all_names).to eq expected_users
    end

  end

end
