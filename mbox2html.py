import html
import mailbox
import os
from email.header import decode_header

import bleach
from bs4 import BeautifulSoup

# Configuration
MBOX_FILE = 'archive.mbox'
OUTPUT_DIR = 'html_archive'

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Allow a small set of safe formatting tags so HTML emails still render nicely
ALLOWED_TAGS = [
    'p', 'br', 'div', 'span', 'strong', 'b', 'em', 'i', 'u',
    'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'hr',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'a', 'img'
]

ALLOWED_ATTRIBUTES = {
    '*': ['class', 'title'],
    'a': ['href', 'title', 'rel'],
    'img': ['src', 'alt', 'title'],
    'th': ['colspan', 'rowspan'],
    'td': ['colspan', 'rowspan'],
}

ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


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
    Sanitize HTML while preserving common formatting used by email content.
    """
    if not raw_html:
        return ""

    # Parse and remove dangerous structural elements first
    soup = BeautifulSoup(raw_html, 'html.parser')
    for tag in soup.find_all(['script', 'iframe', 'object', 'embed', 'applet', 'meta', 'link', 'style']):
        tag.decompose()

    cleaned = str(soup)

    # Strong allowlist-based sanitizer
    cleaned = bleach.clean(
        cleaned,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )

    # Add rel="noopener noreferrer" to links for safety
    cleaned = bleach.linkify(
        cleaned,
        callbacks=[bleach.callbacks.nofollow, bleach.callbacks.target_blank]
    )

    return cleaned


def escape_pre_text(text):
    return f"<pre>{html.escape(text)}</pre>"


def decode_part_payload(part):
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or 'utf-8'
    return payload.decode(charset, errors='ignore')


def extract_best_body(message):
    """
    Prefer text/html over text/plain, while avoiding obvious attachments.
    """
    html_body = None
    text_body = None

    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()
            disposition = (part.get_content_disposition() or '').lower()

            # Skip attachments
            if disposition == 'attachment':
                continue

            decoded = decode_part_payload(part)
            if not decoded:
                continue

            if content_type == 'text/html' and html_body is None:
                html_body = decoded
            elif content_type == 'text/plain' and text_body is None:
                text_body = decoded
    else:
        decoded = decode_part_payload(message)
        if decoded:
            if message.get_content_type() == 'text/html':
                html_body = decoded
            else:
                text_body = decoded

    if html_body is not None:
        return sanitize_html(html_body)

    if text_body is not None:
        return escape_pre_text(text_body)

    return "<pre>(No body content)</pre>"


mbox = mailbox.mbox(MBOX_FILE)

print("Starting secure extraction...")
for idx, message in enumerate(mbox):
    subject = html.escape(decode_mime_header(message['subject']))
    msg_from = html.escape(decode_mime_header(message['from']))
    date = html.escape(decode_mime_header(message['date']))

    sanitized_body = extract_best_body(message)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Email {idx}: {subject}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; line-height: 1.5; color: #333; }}
        .metadata {{ background: #f4f4f4; padding: 10px; border-left: 4px solid #0066cc; margin-bottom: 20px; }}
        .content {{ padding: 10px; border: 1px solid #ddd; background: #fff; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        img {{ max-width: 100%; height: auto; }}
        table {{ border-collapse: collapse; }}
        td, th {{ border: 1px solid #ddd; padding: 4px; }}
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

    safe_filename = f"email_{idx}.html"
    with open(os.path.join(OUTPUT_DIR, safe_filename), "w", encoding="utf-8") as f:
        f.write(html_content)

print(f"Extraction complete. {len(mbox)} files securely saved locally inside: {OUTPUT_DIR}")
