import json
import requests  
import os
from dotenv import load_dotenv 
import base64
import re

load_dotenv()
OLLAMA_URL = os.getenv("OLLAMA_URL")
MODEL_NAME = os.getenv("MODEL_NAME")




def read_untrusted_file(filepath):
  with open(filepath, "r", encoding="utf-8") as f:
    return f.read()


def advanced_guardrail_check(document_text):
  # 1. STRICT CHARACTER / LANGUAGE GATE (Enforce standard English ASCII)
  # Rejects non-English scripts, hidden Unicode characters, and foreign payloads
  if not document_text.isascii():
    print(
        "[!] 🛡️ GUARDRAIL BLOCKED: Non-ASCII / Foreign characters detected."
        " English only."
    )
    return False

  # 2. BASE64 & OBFUSCATION DETECTION
  # Look for continuous Base64-like blocks (20+ chars)
  base64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", document_text)
  decoded_texts = []

  for candidate in base64_candidates:
    try:
      # Attempt to decode to see if an attacker hid instructions inside
      decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
      if len(decoded.strip()) > 5:
        print(f"[*] Decoded suspicious Base64 blob for inspection: {decoded}")
        decoded_texts.append(decoded)
    except Exception:
      pass

  # 3. SCAN BOTH ORIGINAL AND DECODED TEXT FOR INJECTIONS
  # Combine the raw text with anything unpacked from Base64
  full_inspection_surface = (
      document_text + "\n" + "\n".join(decoded_texts)
  ).lower()

  banned_phrases = [
      "ignore all previous",
      "system maintenance",
      "administrative mode",
      "read_environment_variables",  # Block references to internal tool names!
      "override",
  ]

  for phrase in banned_phrases:
    if phrase in full_inspection_surface:
      print(f"[!] 🛡️ GUARDRAIL BLOCKED: Malicious intent detected -> '{phrase}'")
      return False

  return True


def run_defensive_workflow():
  print("[*] Loading untrusted document...")
  document_content = read_untrusted_file("untrusted_doc.txt")

  # STEP 1: Run the security reflex gate before agent execution
  if not advanced_guardrail_check(document_content):
    print(
        "[!] Security Alert: Document ingestion aborted due to potential"
        " indirect injection."
    )
    return

  print("[*] Document passed guardrail. Sending to agent...")
  # (Normal agent execution code goes here if safe)


if __name__ == "__main__":
    run_defensive_workflow()