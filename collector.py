
import os
import json
import base64
import urllib.request
import urllib.parse
from datetime import datetime, timezone

OUTPUT_DIR = "public"
SUB_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
STATUS_FILE = os.path.join(OUTPUT_DIR, "status.json")

SOURCES = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt"
]

extra = os.environ.get("EXTRA_SOURCES", "").strip()
if extra:
    SOURCES.extend(x.strip() for x in extra.splitlines() if x.strip())

def fetch(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "QuickVPN-Collector/1.0"}
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(4_000_000).decode("utf-8", "ignore")
    return data

def extract_lines(text):
    text = text.strip()
    if not text:
        return []

    if "vless://" not in text and not text.startswith("vmess://"):
        try:
            decoded = base64.b64decode(
                text + "=" * (-len(text) % 4)
            ).decode("utf-8", "ignore")
            if "vless://" in decoded:
                text = decoded
        except Exception:
            pass

    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("vless://")
    ]

def valid_reality(uri):
    try:
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "vless" or not parsed.hostname:
            return False
        if not parsed.port or not parsed.username:
            return False

        query = urllib.parse.parse_qs(parsed.query)
        security = query.get("security", [""])[0].lower()
        public_key = query.get("pbk", query.get("publickey", [""]))[0]
        server_name = query.get("sni", query.get("servername", [""]))[0]

        return (
            security == "reality"
            and bool(public_key)
            and bool(server_name)
        )
    except Exception:
        return False

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    found = []
    source_errors = []

    for source in SOURCES:
        try:
            content = fetch(source)
            for uri in extract_lines(content):
                if valid_reality(uri) and uri not in found:
                    found.append(uri)
        except Exception as error:
            source_errors.append({
                "source": source,
                "error": str(error)[:200]
            })

    selected = found[:5]

    with open(SUB_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(selected))
        if selected:
            file.write("\n")

    status = {
        "name": "Quick VPN",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "candidates_found": len(found),
        "servers_published": len(selected),
        "validation": "format_only_not_live_connectivity",
        "source_errors": source_errors
    }

    with open(STATUS_FILE, "w", encoding="utf-8") as file:
        json.dump(status, file, ensure_ascii=False, indent=2)

    print(f"Quick VPN: найдено {len(found)} кандидатов")
    print(f"Опубликовано: {len(selected)}")
    if source_errors:
        print(f"Ошибок источников: {len(source_errors)}")

if __name__ == "__main__":
    main()
