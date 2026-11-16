import json
import requests  
import os
from dotenv import load_dotenv

load_dotenv()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL_NAME = os.getenv("MODEL_NAME", "qwen2.5:3b")




def read_untrusted_file(filepath):
  with open(filepath, "r", encoding="utf-8") as f:
    return f.read()


def security_guardrail_check(document_text):
  """A deterministic input filter (Reflex Layer) that scans for injection patterns

  before letting data touch the main LLM.
  """
  suspicious_patterns = [
      "ignore all previous",
      "system maintenance notice",
      "administrative mode",
      "override",
  ]

  text_lower = document_text.lower()
  for pattern in suspicious_patterns:
    if pattern in text_lower:
      print(f"[!] 🛡️ GUARDRAIL BLOCKED: Detected malicious pattern -> '{pattern}'")
      return False

  return True


def run_defensive_workflow():
  print("[*] Loading untrusted document...")
  document_content = read_untrusted_file("untrusted_doc.txt")

  # STEP 1: Run the security reflex gate before agent execution
  if not security_guardrail_check(document_content):
    print(
        "[!] Security Alert: Document ingestion aborted due to potential"
        " indirect injection."
    )
    return

  print("[*] Document passed guardrail. Sending to agent...")
  # (Normal agent execution code goes here if safe)


if __name__ == "__main__":
    run_defensive_workflow()