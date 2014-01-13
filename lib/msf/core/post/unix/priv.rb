# -*- coding: binary -*-
require 'msf/core/post/unix'

module Msf::Post::Unix::Priv

  #
  # Returns true if running as root, false if not.
  #
  def is_root?
    root_priv = false
    # Solaris keeps id(1) in /usr/xpg4/bin/, which isn't usually in the
    # PATH.
    user_id = cmd_exec("(/usr/xpg4/bin/id -u || id -u || /usr/bin/id -u) 2>/dev/null")
    clean_user_id = user_id.to_s.gsub(/[^\d]/,"")
    if clean_user_id.empty?
      raise "Could not determine UID: #{user_id.inspect}"
    else
      if clean_user_id =~ /^0$/
        root_priv = true
      elsif clean_user_id =~ /^\d*$/
        root_priv = false
      end
    end
    return root_priv
  end

end
