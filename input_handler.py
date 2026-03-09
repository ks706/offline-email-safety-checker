"""
input_handler.py
----------------
Handles all email input for the Offline Email Safety Checker.
Supports two modes:
  1. Paste email text directly into the terminal
  2. Load from a local .txt or .eml file

Returns a structured dictionary of email fields for use by the parser/scanner.

Authors: Karman, Sahail, Adam
Course:  ITSC 203
"""

import os
import sys
import email
import email.policy
from email import message_from_string, message_from_file


# ─────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────

def get_email_input():
    """
    Prompts the user to choose an input method, collects the email,
    and returns a structured dictionary of its fields.

    Returns:
        dict: Parsed email data (see build_email_dict for structure), 
              or None if the user quits.
    """
    sys.stdout.flush()
    print("\n╔══════════════════════════════════════════╗")
    sys.stdout.flush()
    print("║     Offline Email Safety Checker         ║")
    sys.stdout.flush()
    print("╚══════════════════════════════════════════╝")
    sys.stdout.flush()
    print("\nHow would you like to provide the email?")
    sys.stdout.flush()
    print("  [1] Paste email text into the terminal")
    sys.stdout.flush()
    print("  [2] Load from a file (.txt or .eml)")
    sys.stdout.flush()
    print("  [Q] Quit\n")
    sys.stdout.flush()

    while True:
        choice = input("Enter your choice: ").strip().lower()

        if choice == "1":
            raw_email = collect_pasted_input()
            break
        elif choice == "2":
            raw_email = load_from_file()
            if raw_email is None:
                # File loading failed — loop back to menu
                continue
            break
        elif choice == "q":
            print("\nExiting. Goodbye.")
            return None
        else:
            print("Invalid choice. Please enter 1, 2, or Q.")

    # Parse the raw email text into a structured dict
    parsed = parse_email(raw_email)
    return parsed


# ─────────────────────────────────────────────
#  Input Mode 1 – Paste into terminal
# ─────────────────────────────────────────────

def collect_pasted_input():
    """
    Lets the user paste multi-line email text directly into the terminal.
    Entry ends when the user types 'END' on its own line.

    Returns:
        str: The raw email text as a single string.
    """
    print("\nPaste your email below.")
    print("When finished, type  END  on a new line and press Enter.\n")
    print("─" * 50)

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            # Handles piped input (e.g. echo "..." | python main.py)
            break

        if line.strip().upper() == "END":
            break
        lines.append(line)

    print("─" * 50)
    raw_text = "\n".join(lines)

    if not raw_text.strip():
        print("[WARNING] No content was entered. Returning empty email.")

    return raw_text


# ─────────────────────────────────────────────
#  Input Mode 2 – Load from file
# ─────────────────────────────────────────────

def load_from_file():
    """
    Prompts for a file path and reads its contents safely.
    Supports .txt (plain text) and .eml (RFC 2822 email format).

    Returns:
        str: The raw email text, or None if loading failed.
    """
    file_path = input("\nEnter the full path to your email file (.txt or .eml): ").strip()

    # Remove surrounding quotes in case the user drag-and-dropped the file
    file_path = file_path.strip('"').strip("'")

    # ── Validate the path ──────────────────────────────────────────
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        return None

    extension = os.path.splitext(file_path)[1].lower()

    if extension not in (".txt", ".eml"):
        print(f"[ERROR] Unsupported file type '{extension}'. Please use .txt or .eml")
        return None

    # ── Read the file ──────────────────────────────────────────────
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            raw_text = f.read()
        print(f"[OK] Loaded file: {os.path.basename(file_path)}")
        return raw_text

    except PermissionError:
        print(f"[ERROR] Permission denied when trying to read: {file_path}")
        return None
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return None


# ─────────────────────────────────────────────
#  Email Parser
# ─────────────────────────────────────────────

def parse_email(raw_text):
    """
    Parses raw email text into a structured dictionary.
    Uses Python's built-in 'email' library to handle both plain
    text pastes and proper RFC 2822 .eml formatted emails.

    Args:
        raw_text (str): The raw email content.

    Returns:
        dict: A dictionary containing extracted email fields.
    """
    # Python's email parser can handle both raw text and proper .eml format
    msg = message_from_string(raw_text, policy=email.policy.default)

    # ── Extract headers ────────────────────────────────────────────
    sender      = str(msg.get("From",     "")).strip()
    recipient   = str(msg.get("To",       "")).strip()
    subject     = str(msg.get("Subject",  "")).strip()
    reply_to    = str(msg.get("Reply-To", "")).strip()
    date        = str(msg.get("Date",     "")).strip()
    return_path = str(msg.get("Return-Path", "")).strip()

    # ── Extract body text ──────────────────────────────────────────
    body = extract_body(msg, raw_text)

    # ── Extract attachments ────────────────────────────────────────
    attachments = extract_attachments(msg)

    # ── Build and return the structured dict ───────────────────────
    parsed = build_email_dict(
        sender      = sender,
        recipient   = recipient,
        subject     = subject,
        reply_to    = reply_to,
        date        = date,
        return_path = return_path,
        body        = body,
        attachments = attachments,
        raw_text    = raw_text
    )

    return parsed


def extract_body(msg, raw_text):
    """
    Extracts the plain-text body from a parsed email message.
    Falls back to the full raw text if no structured body is found
    (common when the user pastes just the body without headers).

    Args:
        msg:      Parsed email.message.Message object.
        raw_text: Original raw string (used as fallback).

    Returns:
        str: The email body text.
    """
    body = ""

    if msg.is_multipart():
        # Walk through each part and grab text/plain sections
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))

            if content_type == "text/plain" and "attachment" not in disposition:
                try:
                    body += part.get_content() + "\n"
                except Exception:
                    body += str(part.get_payload(decode=True) or "") + "\n"
    else:
        # Single-part message
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload(decode=True) or "")

    # Fallback: if nothing was extracted, use the raw text as the body
    # (handles plain pastes that have no email headers at all)
    if not body.strip():
        body = raw_text

    return body.strip()


def extract_attachments(msg):
    """
    Scans the email for attachments and collects their filenames
    and MIME types. Does NOT open or execute attachment content.

    Args:
        msg: Parsed email.message.Message object.

    Returns:
        list[dict]: Each item has 'filename' and 'mime_type' keys.
    """
    attachments = []

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            filename  = part.get_filename() or "unknown_filename"
            mime_type = part.get_content_type() or "unknown"
            attachments.append({
                "filename":  filename,
                "mime_type": mime_type
            })

    return attachments


def build_email_dict(sender, recipient, subject, reply_to,
                     date, return_path, body, attachments, raw_text):
    """
    Assembles all extracted fields into a clean, consistent dictionary
    that the rest of the program (parser, scanner, scorer) will use.

    Args:
        sender, recipient, subject, reply_to,
        date, return_path (str): Header fields.
        body         (str):  Plain-text body.
        attachments  (list): List of attachment dicts.
        raw_text     (str):  Original unmodified input.

    Returns:
        dict: Structured email data.
    """
    return {
        "headers": {
            "from":         sender,
            "to":           recipient,
            "subject":      subject,
            "reply_to":     reply_to,
            "date":         date,
            "return_path":  return_path,
        },
        "body":        body,
        "attachments": attachments,   # list of {"filename": ..., "mime_type": ...}
        "raw":         raw_text       # kept for any regex-based scanning later
    }


# ─────────────────────────────────────────────
#  Quick debug helper
# ─────────────────────────────────────────────

def print_parsed_summary(parsed):
    """
    Prints a readable summary of parsed email fields.
    Useful during development and testing.

    Args:
        parsed (dict): Output of parse_email().
    """
    if parsed is None:
        print("No email data to display.")
        return

    h = parsed["headers"]
    print("\n── Parsed Email Summary ─────────────────────")
    print(f"  From:         {h['from']        or '(not found)'}")
    print(f"  To:           {h['to']          or '(not found)'}")
    print(f"  Subject:      {h['subject']     or '(not found)'}")
    print(f"  Reply-To:     {h['reply_to']    or '(not found)'}")
    print(f"  Date:         {h['date']        or '(not found)'}")
    print(f"  Return-Path:  {h['return_path'] or '(not found)'}")
    print(f"  Attachments:  {len(parsed['attachments'])}")
    for att in parsed["attachments"]:
        print(f"    → {att['filename']} ({att['mime_type']})")
    print(f"  Body preview: {parsed['body'][:120].replace(chr(10), ' ')}...")
    print("─────────────────────────────────────────────\n")


# ─────────────────────────────────────────────
#  Standalone test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Run this file directly to test input handling on its own
    result = get_email_input()
    print_parsed_summary(result)