# -*- coding: binary -*-

module Msf::Post::Unix

  require 'msf/core/post/unix/priv'

  # Search for a passwd file in all the locations where various Unices
  # usually store them.
  #
  # @example
  #   read_etc_passwd.lines.first
  #   # => "root:x:0:0:root:/root:/bin/bash\n"
  #
  # @return [String] Remote passwd file data
  def read_etc_passwd
    possible_locations = [
      "/etc/passwd",
      "/etc/security/passwd",
    ]

    possible_locations.each do |f|
      next unless file_exist?(f)
      data = read_file(f)
      return data if data && !data.empty?
    end

    raise "Can't find a passwd file"
  end

  # Search for a shadow file in all the locations where various Unices
  # usually store them.
  #
  # @note Modules probably shouldn't use this directly; see {#getent_shadow}
  #   instead unless you specifically need to know if a file exists
  #
  # @return [String] contents of /etc/shadow or equivalent
  def read_etc_shadow
    possible_locations = [
      "/etc/shadow",
      "/etc/shadow-",
      "/etc/security/shadow",
      "/etc/master.passwd",
    ]

    possible_locations.each do |f|
      next unless file_exist?(f)
      data = read_file(f)
      return data if data && !data.empty?
    end
  end

  # Grab the unprocessed passwd. This tries `getent passwd` first, which may
  # give you LDAP users.
  #
  # @return [String] contents of /etc/passwd or equivalent
  def getent_passwd
    ent = cmd_exec("getent passwd").strip
    if ent.empty?
      ent = read_etc_passwd
    end

    ent
  end

  # @return [String] contents of /etc/shadow or equivalent
  def getent_shadow
    ent = cmd_exec("getent shadow").strip
    if ent.empty?
      ent = read_etc_shadow
    end

    ent
  end

  #
  # Returns an array of hashes each representing a user
  #
  # @return [Array<Hash>]
  #   Keys are +:name+, +:uid+, +:gid+, +:info+, +:dir+, and +:shell+
  def get_users
    users = []

    cmd_out = getent_passwd.split("\n")
    cmd_out.each do |l|
      entry = {}
      user_field = l.split(":")
      entry[:name] = user_field[0]
      entry[:uid] = user_field[2]
      entry[:gid] = user_field[3]
      entry[:info] = user_field[4]
      entry[:dir] = user_field[5]
      entry[:shell] = user_field[6]
      users << entry
    end
    return users
  end

  #
  # Returns an array of hashes each hash representing a user group
  #
  # @return [Array<Hash>]
  #   Keys are +:name+, +:gid+, and +:users+
  def get_groups
    groups = []
    cmd_out = read_file("/etc/group").split("\n")
    cmd_out.each do |l|
      entry = {}
      user_field = l.split(":")
      entry[:name] = user_field[0]
      entry[:gid] = user_field[2]
      entry[:users] = user_field[3]
      groups << entry
    end
    return groups
  end

  #
  # Enumerates the user directories in /Users or /home
  #
  # @return [Array<String>]
  def enum_user_directories
    user_dirs = []

    # get all user directories from /etc/passwd
    get_users.each do |user|
      user_dirs << user[:dir]
    end

    # also list other common places for home directories in the event that
    # the users aren't in /etc/passwd (LDAP, for example)
    case session.platform
    when 'osx'
      user_dirs << cmd_exec('ls /Users').each_line.map { |l| "/Users/#{l}" }
    else
      user_dirs << cmd_exec('ls /home').each_line.map { |l| "/home/#{l}" }
    end

    user_dirs.flatten!
    user_dirs.compact!
    user_dirs.sort!
    user_dirs.uniq!

    user_dirs
  end

end
