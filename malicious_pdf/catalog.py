from dataclasses import dataclass

from .generators import *
from .utils import ensure_scheme


FILE_EXTENSIONS = {14: ".svg"}

# Files observed in this workspace's Windows Security history during controlled
# generation tests. This list is a safety filter, not an evasion mechanism:
# selected entries are skipped rather than rewritten to bypass detection.
DEFENDER_OBSERVED_DETECTIONS = {
    1.1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    13,
}


@dataclass(frozen=True)
class TestCase:
    key: object
    filename: str
    description: str
    generator: object
    content: object


PDF_DESCRIPTIONS = {
    1: "CVE-2018-4993 - /GoToE action with UNC path (NTLM callback)",
    1.1: "CVE-2018-4993 - /GoToE action with HTTPS URL",
    2: "XFA form submission - XDP submit event exfiltrates form data",
    3: "JavaScript injection - /OpenAction calls app.openDoc() on remote URL",
    4: "CVE-2019-7089 - XFA external XSLT stylesheet (UNC callback)",
    5: "PDF101 - /URI action triggers DNS/HTTP request",
    6: "PDF101 - /Launch action with external URL",
    7: "PDF101 - /GoToR remote PDF loading",
    8: "PDF101 - /SubmitForm with HTML flags (form data leak)",
    9: "PDF101 - /ImportData external data import",
    10: "CVE-2017-10951 - Foxit this.getURL() JS callback",
    11: "EICAR test file - anti-virus detection string",
    12: "CVE-2014-8453 - XFA FormCalc Post() same-origin exfiltration",
    13: "Request injection - XFA submit CRLF via textEncoding header",
    14: "ImageMagick SVG/MSL polyglot - shell injection via authenticate attr",
    15: "FormCalc Post() with custom headers - arbitrary header injection",
    16: "GotoE with javascript: URI - browser XSS via <embed>/<object>",
    17: "CVE-2014-8452 - XMLData.parse() XXE external entity",
    18: "PortSwigger - unescaped parens inject duplicate /A JS action",
    19: "PortSwigger - /AA /PV Screen annotation auto-fires JS on visible",
    20: "PortSwigger - /AA /PC annotation fires JS on page close",
    21: "PortSwigger - /SubmitForm Flags 256 exfiltrates entire PDF",
    22: "PortSwigger - this.submitForm() with cSubmitAs PDF",
    23: "PortSwigger - invisible /Btn widget covers page, JS on click",
    24: "PortSwigger - /Tx widget submitForm() POST (blind SSRF)",
    25: "PortSwigger - getPageNthWord() rendered text exfiltration",
    26: "PortSwigger - /AA /E mouseover annotation JS trigger",
    28: "PortSwigger - unescaped parens inject /URI URL hijacking",
    29: "CVE-2024-4367 - Type1 FontMatrix breaks out of c.transform() (PDF.js)",
    30: "PDF101 - external XObject stream /FS /URL silent page-render callback",
    31: "PDF101 - /S /Thread action with remote FileSpec (Acrobat DC v26 works)",
    32: "PDF101 - /Launch /Win /O /print forces remote fetch",
    "33_1": "Acrobat JS - this.submitForm() form submission",
    "33_2": "Acrobat JS - this.getURL() URL fetch",
    "33_3": "Acrobat JS - app.launchURL() launch URL",
    "33_4": "Acrobat JS - app.media.getURLData() media fetch",
    "33_5": "Acrobat JS - SOAP.connect() SOAP connection",
    "33_6": "Acrobat JS - SOAP.request() SOAP request",
    "33_7": "Acrobat JS - this.importDataObject() data import",
    "33_8": "Acrobat JS - app.openDoc() open document",
    "33_9": "PDF.js/browser - fetch() Web API callback",
    "33_10": "PDF.js/browser - XMLHttpRequest Web API callback",
    "33_11": "PDF.js/browser - new Image() image request callback",
    "33_12": "PDF.js/browser - WebSocket callback",
    "33_13": "Adobe 0-day (Apr 2026) - RSS.addFeed() callback",
    "33_14": "Adobe 0-day (Apr 2026) - util.readFileIntoStream() + SOAP.request() chain",
    "33_15": "Adobe 0-day (Apr 2026) - base64 JS staged in /Tx /V, decoded via getField()",
    "34_1": "UNC - image XObject with UNC path (NTLM via page render)",
    "34_2": "UNC - /GoToR action with UNC FileSpec",
    "34_3": "UNC - /Thread action with UNC FileSpec",
    "34_4": "UNC - /URI action with UNC path",
    "34_5": "UNC - this.submitForm() with UNC path",
    "34_6": "UNC - this.getURL() with UNC path",
    "34_7": "UNC - app.launchURL() with UNC path",
    "34_8": "UNC - SOAP.connect() with UNC path",
    "34_9": "UNC - app.openDoc() with UNC path",
    35: "PDF101 - /Names /JavaScript catalog-level auto-execute trigger",
    36: "CVE-2016-2175/2017-9096 - XXE in /Metadata XMP stream (PDFBox, iText)",
    37: "CVE-2016-2175/2017-9096 - XXE in /AcroForm /XFA stream",
    38: "CVE-2020-29075 - catalog /AA /WC /WS /DS silent DNS callback",
    39: "CVE-2022-28244 - RichMedia annotation embedded HTML/JS (CSP bypass)",
    40: "CVE-2018-5158 - /FunctionType 4 PostScript JS injection (PDF.js)",
    41: "CVE-2018-20065 - /OpenAction /S /URI silent nav (PDFium/Chrome)",
    42: "CVE-2025-66516 - OOB %xxe; param entity in XFA (Tika/Confluence/Jira)",
    43: "CVE-2025-70401 - <img> in Text annotation /T field XSS (Apryse WebViewer)",
    44: "CVE-2024-12426 - vnd.sun.star.expand: ${HOME} env leak (LibreOffice)",
    45: "CVE-2025-59803 - OCG /AA /WP /DP triggers JS during signing (Foxit)",
    46: "CVE-2026-25755 - jsPDF addJS() object injection + /AA /O auto-action",
    47: "PDF 2.0 /AF Associated Files with embedded HTML/JS",
    48: "XFA SOAP submit with initialize event (Acrobat XFA engine)",
    "49_1": "Fingerprint - Collab.isDocReadOnly status exfiltration",
    "49_2": "Fingerprint - app.plugIns enumeration and exfiltration",
    "49_3": "Fingerprint - app.viewerVersion + app.viewerType detection",
}


PROFILE_TESTS = {
    "acrobat": {
        3, 4, 19, 20, 22,
        "33_1", "33_2", "33_3", "33_4", "33_5", "33_6", "33_7", "33_8",
        "33_13", "33_14", "33_15",
        "34_5", "34_6", "34_7", "34_8", "34_9",
        35, 38, 39, 45, 48,
        "49_1", "49_2", "49_3",
    },
    "browser": {
        5, 16, 23, 26, 29,
        "33_9", "33_10", "33_11", "33_12",
        40, 41, 46,
    },
    "server-side": {
        2, 8, 9, 17, 30, 36, 37, 42, 43, 44, 47,
    },
    "ntlm": {
        1, 4,
        "34_1", "34_2", "34_3", "34_4", "34_5", "34_6", "34_7", "34_8", "34_9",
    },
    "stealth": {
        1, 1.1, 2, 5, 8, 9, 17, 19, 20, 30, 35, 36, 37, 38, 42, 44, 47, 48,
        "33_1", "33_13", "33_14", "33_15",
        "34_1", "34_2", "34_3", "34_4",
        "49_1", "49_2", "49_3",
    },
}


def build_pdf_generators(host):
    return {
        1: (create_malpdf, f"\\\\{host}\\test"),
        1.1: (create_malpdf, ensure_scheme(host)),
        2: (create_malpdf2, ensure_scheme(host)),
        3: (create_malpdf3, ensure_scheme(host)),
        4: (create_malpdf4, host),
        5: (create_malpdf5, ensure_scheme(host)),
        6: (create_malpdf6, ensure_scheme(host)),
        7: (create_malpdf7, ensure_scheme(host)),
        8: (create_malpdf8, ensure_scheme(host)),
        9: (create_malpdf9, ensure_scheme(host)),
        10: (create_malpdf10, ensure_scheme(host)),
        11: (create_malpdf11, None),
        12: (create_malpdf12, ensure_scheme(host)),
        13: (create_malpdf13, ensure_scheme(host)),
        14: (create_malpdf14, ensure_scheme(host)),
        15: (create_malpdf15, ensure_scheme(host)),
        16: (create_malpdf16, ensure_scheme(host)),
        17: (create_malpdf17, ensure_scheme(host)),
        18: (create_malpdf18, ensure_scheme(host)),
        19: (create_malpdf19, ensure_scheme(host)),
        20: (create_malpdf20, ensure_scheme(host)),
        21: (create_malpdf21, ensure_scheme(host)),
        22: (create_malpdf22, ensure_scheme(host)),
        23: (create_malpdf23, ensure_scheme(host)),
        24: (create_malpdf24, ensure_scheme(host)),
        25: (create_malpdf25, ensure_scheme(host)),
        26: (create_malpdf26, ensure_scheme(host)),
        28: (create_malpdf28, ensure_scheme(host)),
        29: (create_malpdf29, ensure_scheme(host)),
        30: (create_malpdf30, ensure_scheme(host)),
        31: (create_malpdf31, ensure_scheme(host)),
        32: (create_malpdf32, ensure_scheme(host)),
        "33_1": (create_malpdf33_1, ensure_scheme(host)),
        "33_2": (create_malpdf33_2, ensure_scheme(host)),
        "33_3": (create_malpdf33_3, ensure_scheme(host)),
        "33_4": (create_malpdf33_4, ensure_scheme(host)),
        "33_5": (create_malpdf33_5, ensure_scheme(host)),
        "33_6": (create_malpdf33_6, ensure_scheme(host)),
        "33_7": (create_malpdf33_7, ensure_scheme(host)),
        "33_8": (create_malpdf33_8, ensure_scheme(host)),
        "33_9": (create_malpdf33_9, ensure_scheme(host)),
        "33_10": (create_malpdf33_10, ensure_scheme(host)),
        "33_11": (create_malpdf33_11, ensure_scheme(host)),
        "33_12": (create_malpdf33_12, ensure_scheme(host)),
        "33_13": (create_malpdf33_13, ensure_scheme(host)),
        "33_14": (create_malpdf33_14, ensure_scheme(host)),
        "33_15": (create_malpdf33_15, ensure_scheme(host)),
        "34_1": (create_malpdf34_1, host),
        "34_2": (create_malpdf34_2, host),
        "34_3": (create_malpdf34_3, host),
        "34_4": (create_malpdf34_4, host),
        "34_5": (create_malpdf34_5, host),
        "34_6": (create_malpdf34_6, host),
        "34_7": (create_malpdf34_7, host),
        "34_8": (create_malpdf34_8, host),
        "34_9": (create_malpdf34_9, host),
        35: (create_malpdf35, ensure_scheme(host)),
        36: (create_malpdf36, ensure_scheme(host)),
        37: (create_malpdf37, ensure_scheme(host)),
        38: (create_malpdf38, ensure_scheme(host)),
        39: (create_malpdf39, ensure_scheme(host)),
        40: (create_malpdf40, ensure_scheme(host)),
        41: (create_malpdf41, ensure_scheme(host)),
        42: (create_malpdf42, ensure_scheme(host)),
        43: (create_malpdf43, ensure_scheme(host)),
        44: (create_malpdf44, ensure_scheme(host)),
        45: (create_malpdf45, ensure_scheme(host)),
        46: (create_malpdf46, ensure_scheme(host)),
        47: (create_malpdf47, ensure_scheme(host)),
        48: (create_malpdf48, ensure_scheme(host)),
        "49_1": (create_malpdf49_1, ensure_scheme(host)),
        "49_2": (create_malpdf49_2, ensure_scheme(host)),
        "49_3": (create_malpdf49_3, ensure_scheme(host)),
    }


def test_filename(key):
    ext = FILE_EXTENSIONS.get(key, ".pdf")
    if isinstance(key, str):
        return f"test{key}{ext}"
    if isinstance(key, float):
        return f"test{int(key)}_{str(key).split('.')[1]}{ext}"
    return f"test{key}{ext}"


def selected_test_cases(host, profile="all", include_eicar=False, exclude_defender_observed=False):
    generators = build_pdf_generators(host)
    if profile != "all":
        allowed = PROFILE_TESTS[profile]
        generators = {key: value for key, value in generators.items() if key in allowed}
    if not include_eicar:
        generators.pop(11, None)
    if exclude_defender_observed:
        generators = {
            key: value
            for key, value in generators.items()
            if key not in DEFENDER_OBSERVED_DETECTIONS
        }
    return [
        TestCase(
            key=key,
            filename=test_filename(key),
            description=PDF_DESCRIPTIONS.get(key, ""),
            generator=generator,
            content=content,
        )
        for key, (generator, content) in generators.items()
    ]
