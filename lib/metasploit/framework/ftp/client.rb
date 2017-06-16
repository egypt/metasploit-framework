# frozen_string_literal: true

require 'metasploit/framework/tcp/client'

module Metasploit
  module Framework
    module Ftp
      module Client
        extend ActiveSupport::Concern
        include Metasploit::Framework::Tcp::Client

        # The banner that was read in after a successful call to {#connect} or
        # {#connect_login}.
        #
        # @return [String]
        attr_accessor :banner

        # The socket created with a PASV connection via {#data_connect}
        #
        # @return [Rex::Socket]
        attr_accessor :datasocket

        #
        # This method establishes an FTP connection to host and port specified by
        # the 'rhost' and 'rport' methods. After connecting, the banner
        # message is read in and stored in the 'banner' attribute.
        #
        def connect(global = true)
          fd = super(global)

          @ftpbuff = '' unless @ftpbuff

          # Wait for a banner to arrive...
          self.banner = recv_ftp_resp(fd)

          # Return the file descriptor to the caller
          fd
        end

        #
        # This method handles establishing datasocket for data channel
        #
        def data_connect(mode = nil, nsock = sock)
          if mode
            res = send_cmd([ 'TYPE', mode ], true, nsock)
            return nil unless res.match?(/^200/)
          end

          # force datasocket to renegotiate
          datasocket.shutdown unless datasocket.nil?

          res = send_cmd(['PASV'], true, nsock)
          return nil unless res.match?(/^227/)

          # 227 Entering Passive Mode (127,0,0,1,196,5)
          if res =~ /\((\d+)\,(\d+),(\d+),(\d+),(\d+),(\d+)/
            # convert port to FTP syntax
            datahost = "#{Regexp.last_match(1)}.#{Regexp.last_match(2)}.#{Regexp.last_match(3)}.#{Regexp.last_match(4)}"
            dataport = (Regexp.last_match(5).to_i * 256) + Regexp.last_match(6).to_i
            self.datasocket = Rex::Socket::Tcp.create(
              'PeerHost' => datahost,
              'PeerPort' => dataport,
              'Context'  => { 'Msf' => framework, 'MsfExploit' => framework_module }
            )
          end
          datasocket
        end

        #
        # Disconnect an open data channel
        #
        def data_disconnect
          datasocket.shutdown
          self.datasocket = nil
        end

        #
        # Connect and login to the remote FTP server using the credentials
        # that have been supplied in the exploit options.
        #
        def connect_login(user, pass)
          connect

          login(user, pass)
        end

        # @return [Bool]
        def login(user, pass, ftpsock = sock)
          return false unless user && pass

          res = send_user(user, ftpsock)

          # 331 is "Username OK, need password"
          return false if res !~ /^(331|2)/

          if pass
            res = send_pass(pass, ftpsock)
            return false if res !~ /^2/
          end
        end

        #
        # Log in as the supplied user by transmitting the FTP
        # `USER <user>` command.
        #
        # @return (see #recv_ftp_resp)
        def send_user(user)
          raw_send("USER #{user}\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method completes user authentication by sending the supplied
        # password using the FTP 'PASS <pass>' command.
        #
        # @return (see #recv_ftp_resp)
        def send_pass(pass, nsock = sock)
          raw_send("PASS #{pass}\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # Send a QUIT command.
        #
        # @return (see #recv_ftp_resp)
        def send_quit(nsock = sock)
          raw_send("QUIT\r\n", nsock)
          recv_ftp_resp(nsock)
        end

        #
        # This method sends one command with zero or more parameters
        #
        def send_cmd(args, recv = true, nsock = sock)
          cmd = args.join(" ") + "\r\n"
          ret = raw_send(cmd, nsock)
          return recv_ftp_resp(nsock) if recv
          ret
        end

        #
        # Transmit the command in `args` and receive / upload DATA via data channel
        #
        # For commands not needing data, it will fall through to the original {#send_cmd}.
        # For commands that send data only, the return will be the server response.
        # For commands returning both data and a server response, an array will be returned.
        #
        # @note This always waits for a response from the server.
        def send_cmd_data(args, data, mode = 'a', nsock = sock)
          type = nil
          # implement some aliases for various commands
          if args[0] =~ /^DIR$/i || args[0] =~ /^LS$/i
            # TODO: || args[0] =~ /^MDIR$/i || args[0] =~ /^MLS$/i
            args[0] = "LIST"
            type = "get"
          elsif args[0].match?(/^GET$/i)
            args[0] = "RETR"
            type = "get"
          elsif args[0].match?(/^PUT$/i)
            args[0] = "STOR"
            type = "put"
          end

          # fall back if it's not a supported data command
          return send_cmd(args, true, nsock) unless type

          # Set the transfer mode and connect to the remove server
          return nil unless data_connect(mode)

          # Our pending command should have got a connection now.
          res = send_cmd(args, true, nsock)
          # make sure could open port
          return nil unless res.match?(/^(150|125) /)

          # dispatch to the proper method
          if type == "get"
            # failed listings jsut disconnect..
            begin
              data = datasocket.get_once(-1, ftp_timeout)
            rescue ::EOFError
              data = nil
            end
          else
            datasocket.put(data)
          end

          # close data channel so command channel updates
          data_disconnect

          # get status of transfer
          ret = nil
          if type == "get"
            ret = recv_ftp_resp(nsock)
            ret = [ ret, data ]
          else
            ret = recv_ftp_resp(nsock)
          end

          ret
        end

        #
        # This method transmits a FTP command and waits for a response.  If one is
        # received, it is returned to the caller.
        #
        def raw_send_recv(cmd, nsock = sock)
          nsock.put(cmd)
          nsock.get_once(-1, ftp_timeout)
        end

        #
        # This method reads an FTP response based on FTP continuation stuff
        #
        def recv_ftp_resp(nsock = sock)
          found_end = false
          resp = ""
          left = ""
          unless @ftpbuff.empty?
            left << @ftpbuff
            @ftpbuff = ""
          end
          loop do
            data = nsock.get_once(-1, ftp_timeout)
            unless data
              @ftpbuff << resp
              @ftpbuff << left
              return data
            end

            got = left + data
            left = ""

            # handle the end w/o newline case
            enlidx = got.rindex(0x0a.chr)
            if enlidx != (got.length - 1)
              if !enlidx
                left << got
                next
              else
                left << got.slice!((enlidx + 1)..got.length)
              end
            end

            # split into lines
            rarr = got.split(/\r?\n/)
            rarr.each do |ln|
              if found_end
                left << ln
                left << "\r\n"
              else
                resp << ln
                resp << "\r\n"
                found_end = true if ln.length > 3 && ln[3, 1] == ' '
              end
            end
            if found_end
              @ftpbuff << left
              return resp
            end
          end
        end

        #
        # This method transmits a FTP command and does not wait for a response
        #
        def raw_send(cmd, nsock = sock)
          nsock.put(cmd)
        end

        def ftp_timeout
          raise NotImplementedError
        end
      end
    end
  end
end
