# -*- coding: binary -*-
require 'msf/core/post/unix'

module Msf::Post::Unix::Priv

  #
  # Returns true if running as root, false if not.
  #
  def is_root?
    # Solaris keeps id(1) in /usr/xpg4/bin/, which isn't usually in the
    # PATH.
    id_output = cmd_exec("(/usr/xpg4/bin/id || id || /usr/bin/id) 2>/dev/null")

    # Linux:
    #   uid=1000(msfadmin) gid=1000(msfadmin) groups=1000(msfadmin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),107(lpadmin),124(sambashare),130(wireshark)
    uid_match = id_output.match(/uid=(\d+)[^ ]?/)
    if uid_match
      clean_user_id = uid_match[1]
    else
      raise "Could not determine UID: #{id_output.inspect}"
    end

    "0" == clean_user_id
  end

end
