##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

  # Has some issues, but overall it's pretty good
  Rank = GoodRanking

  def initialize
    super(
      'Name'             => 'Generic Shell Variable Substitution Command Encoder',
      'Description'      => %q{
        This encoder uses standard Bourne shell variable substitution
      tricks to avoid commonly restricted characters.
      },
      'Author'           => 'hdm',
      'Arch'             => ARCH_CMD)
  end


  #
  # Encodes the payload
  #
  def encode_block(state, buf)

    # Skip encoding for empty badchars
    if(state.badchars.length == 0)
      return buf
    end

    if (state.badchars.include?("-"))
      # Then neither of the others will work.  Get rid of spaces and hope
      # for the best.  This obviously won't work if the command already
      # has other badchars in it, in which case we're basically screwed.
      if (state.badchars.include?(" "))
        buf.gsub!(/\s/, '${IFS}')
      end
    else
      # Without an escape character we can't escape anything, so echo
      # won't work.  Try perl.
      if (state.badchars.include?("\\"))
        buf = encode_block_perl(state,buf)
      else
        buf = encode_block_bash_echo(state,buf)
      end
    end

    return buf
  end

  #
  # Uses the perl command to hex encode the command string
  #
  def encode_block_perl(state, buf)

    hex = buf.unpack("H*").join
    cmd = 'perl -e '
    qot = ',-:.=+!@#$%^&'

    # Convert spaces to IFS...
    if (state.badchars.include?(" "))
      if state.badchars.match(/[${IFS}]/n)
        raise RuntimeError
      end
      cmd.gsub!(/\s/, '${IFS}')
    end

    # Can we use single quotes to enclose the command string?
    if (state.badchars.include?("'"))

      if (state.badchars.match(/[()\\]/))
        # We don't have parens, quotes, or backslashes so we have to use
        # barewords on the commandline for the argument to the pack
        # function. As a consequence, we can't use things that the shell
        # would interpret, so $ and & become badchars.
        qot.delete("$")
        qot.delete("&")

        # Perl chains -e with newlines, but doesn't automatically add
        # semicolons, so the following will result in the interpreter
        # seeing a file like this:
        #    system
        #    pack
        #    qq^H*^,qq^whatever^
        # Since system and pack require arguments (rather than assuming
        # $_ when no args are given like many other perl functions),
        # this works out to do what we need.
        cmd << "system -e pack -e #{perl_qq(state, qot, hex)}"
        if state.badchars.include?(" ")
          # We already tested above to make sure that these chars are ok
          # if space isn't.
          cmd.gsub!(" ", "${IFS}")
        end
      else
        # Without quotes, we can use backslash to escape parens so the
        # shell doesn't try to interpreter them.
        cmd << "system\\(pack\\(#{perl_qq(state, qot, hex)})\\)"
      end

    else
      # Quotes are ok, but we still need parens or spaces
      if (state.badchars.match(/[()]/n))
        if (state.badchars.include?(" "))
          # No spaces allowed, no paranthesis, give up...
          raise RuntimeError
        end

        cmd << "'system pack #{perl_qq(state, qot, hex)}'"
      else
        cmd << "'system(pack(#{perl_qq(state, qot, hex)}))'"
      end
    end

    return cmd
  end

  #
  # Uses bash's echo -ne command to hex encode the command string
  #
  def encode_block_bash_echo(state, buf)

    hex = ''

    # Can we use single quotes to enclose the echo arguments?
    if (state.badchars.include?("'"))
      hex = buf.unpack('C*').collect { |c| "\\\\\\x%.2x" % c }.join
    else
      hex = "'" + buf.unpack('C*').collect { |c| "\\x%.2x" % c }.join + "'"
    end

    # Are pipe characters restricted?
    if (state.badchars.include?("|"))
      # How about backticks?
      if (state.badchars.include?("`"))
        # Last ditch effort, dollar paren
        if (state.badchars.include?("$") or state.badchars.include?("("))
          # No shell stuff, try perl
          return encode_block_perl(state, buf)
        else
          buf = "$(/bin/echo -ne #{hex})"
        end
      else
        buf = "`/bin/echo -ne #{hex}`"
      end
    else
      buf = "/bin/echo -ne #{hex}|sh"
    end

    # Remove spaces from the command string
    if (state.badchars.include?(" "))
      buf.gsub!(/\s/, '${IFS}')
    end

    return buf
  end

  def perl_qq(state, qot, hex)

    # Find a quoting character to use
    state.badchars.unpack('C*') { |c| qot.delete(c.chr) }

    # Throw an error if we ran out of quotes
    raise RuntimeError if qot.length == 0

    sep = qot[0].chr
    # Use an explicit length for the H specifier instead of just "H*"
    # in case * is a badchar for the module, and for the case where this
    # ends up unquoted so the shell doesn't try to expand a path.
    "qq#{sep}H#{hex.length}#{sep},qq#{sep}#{hex}#{sep}"
  end

end
