import os, time, requests
from dotenv import load_dotenv
load_dotenv()

def send(text):
    url = f"https://api.telegram.org/bot{os.environ['TELEGRAM_BOT_TOKEN']}/sendMessage"
    for i, chunk in enumerate(_split(text), 1):
        requests.post(url, json={"chat_id": os.environ["TELEGRAM_CHAT_ID"], "text": chunk}, timeout=10).raise_for_status()
        print(f"[telegram] Chunk {i} sent.")
        time.sleep(0.5)

def _split(text, n=4000):
    if len(text) <= n: return [text]
    chunks, w = [], text
    while w:
        if len(w) <= n: chunks.append(w); break
        i = w.rfind("\n", 0, n)
        if i == -1: i = n
        chunks.append(w[:i]); w = w[i:].lstrip()
    return chunks
