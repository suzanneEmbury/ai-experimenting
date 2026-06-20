import mailbox
import os
import re
from email.header import decode_header
from bs4 import BeautifulSoup

# Configuration
MBOX_FILE = 'archive.mbox'
OUTPUT_DIR = 'html_archive'

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def decode_mime_header(header_value):
    if not header_value:
        return "Unknown"
    decoded = decode_header(header_value)
    header_parts = []
    for bytes_or_str, encoding in decoded:
        if isinstance(bytes_or_str, bytes):
            header_parts.append(bytes_or_str.decode(encoding or 'utf-8', errors='ignore'))
        else:
            header_parts.append(bytes_or_str)
    return "".join(header_parts)

def sanitize_html(raw_html):
    """
    Parses the HTML locally and strips out executable scripts and dangerous attributes.
    """
    if not raw_html.strip():
        return ""
    
    # Use BeautifulSoup to parse the document locally
    soup = BeautifulSoup(raw_html, 'html.parser')
    
    # 1. Remove inherently dangerous structural tags
    blacklisted_tags = ['script', 'iframe', 'object', 'embed', 'applet', 'meta', 'link']
    for tag in soup.find_all(blacklisted_tags):
        tag.decompose()
        
    # 2. Remove inline JavaScript event handlers (e.g., onload, onerror, onclick)
    # and dangerous javascript: pseudo-protocols in links
    for tag in soup.find_all(True):
        # Clear attributes that start with 'on' (javascript events)
        attrs_to_remove = [attr for attr in tag.attrs if attr.lower().startswith('on')]
        for attr in attrs_to_remove:
            del tag[attr]
            
        # Check href attributes for javascript: links
        if tag.has_attr('href'):
            if tag['href'].strip().lower().startswith('javascript:'):
                tag['href'] = '#'
                
        if tag.has_attr('src'):
            if tag['src'].strip().lower().startswith('javascript:'):
                del tag['src']

    return str(soup)

mbox = mailbox.mbox(MBOX_FILE)

print("Starting secure extraction...")
for idx, message in enumerate(mbox):
    subject = decode_mime_header(message['subject'])
    msg_from = decode_mime_header(message['from'])
    date = decode_mime_header(message['date'])
    
    # Extract the body
    body = ""
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/html':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                break
            elif content_type == 'text/plain' and not body:
                body = f"<pre>{part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')}</pre>"
    else:
        payload = message.get_payload(decode=True)
        charset = message.get_content_charset() or 'utf-8'
        if message.get_content_type() == 'text/html':
            body = payload.decode(charset, errors='ignore')
        else:
            body = f"<pre>{payload.decode(charset, errors='ignore')}</pre>"

    # Sanitize the extracted body payload
    sanitized_body = sanitize_html(body)

    # Construct secure HTML Wrapper
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Email {idx}: {subject}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; line-height: 1.5; color: #333; }}
        .metadata {{ background: #f4f4f4; padding: 10px; border-left: 4px solid #0066cc; margin-bottom: 20px; }}
        .content {{ padding: 10px; border: 1px solid #ddd; background: #fff; }}
    </style>
</head>
<body>
    <div class="metadata">
        <strong>From:</strong> {msg_from}<br>
        <strong>Date:</strong> {date}<br>
        <strong>Subject:</strong> {subject}
    </div>
    <div class="content">
        {sanitized_body}
    </div>
</body>
</html>"""

    # Fix path traversal: Name files sequentially rather than using user-controlled subject lines
    safe_filename = f"email_{idx}.html"
    with open(os.path.join(OUTPUT_DIR, safe_filename), "w", encoding="utf-8") as f:
        f.write(html_content)

print(f"Extraction complete. {len(mbox)} files securely saved locally inside: {OUTPUT_DIR}")
