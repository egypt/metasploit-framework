# -*- coding: binary -*-

module Msf::Post::Unix

  require 'msf/core/post/unix/priv'

  # Search for a passwd file in all the locations where various Unices
  # usually store them.
  #
  # @return [String] Path to remote passwd file, e.g. "/etc/passwd"
  def find_etc_passwd
    possible_locations = [
      "/etc/passwd",
      "/etc/security/passwd",
    ]

    possible_locations.find { |f| file_exist?(f) }
  end

  # Search for a shadow file in all the locations where various Unices
  # usually store them.
  #
  # @return [String] Path to remote shadow file, e.g. "/etc/shadow"
  def find_etc_shadow
    possible_locations = [
      "/etc/shadow",
      "/etc/shadow-",
      "/etc/security/shadow",
      "/etc/master.passwd",
    ]

    possible_locations.find { |f| file_exist?(f) }
  end

  def getent_passwd
    ent = cmd_exec("getent passwd").strip
    if ent.empty?
      etc_passwd = find_etc_passwd
      if etc_passwd
        ent = read_file(etc_passwd)
      end
    end

    ent
  end

  def getent_shadow
    ent = cmd_exec("getent shadow").strip
    if ent.empty?
      etc_shadow = find_etc_shadow
      if etc_shadow
        ent = read_file(etc_shadow)
      end
    end

    ent
  end


  #
  # Returns an array of hashes each representing a user
  #
  # Keys are +:name+, +:uid+, +:gid+, +:info+, +:dir+, and +:shell+
  #
  # @return [Array<Hash>]
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
  # Keys are +:name+, +:gid+, and +:users+
  #
  # @return [Array<Hash>]
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
    etc_passwd = find_etc_passwd

    # get all user directories from /etc/passwd
    read_file(etc_passwd).each_line do |passwd_line|
      user_dirs << passwd_line.split(/:/)[5]
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
