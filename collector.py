
import base64
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qs

SOURCES = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt",
]

# Дополнительные HTTPS-источники через переменную окружения.
EXTRA = os.environ.get("EXTRA_SOURCES", "")
SOURCES += [
    item.strip()
    for item in EXTRA.split(",")
    if item.strip().startswith("https://")
]

MAX_BYTES = 8 * 1024 * 1024


def fetch(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "HappSubscriptionCollector/1.0"},
    )

    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(MAX_BYTES + 1)

    if len(data) > MAX_BYTES:
        raise ValueError("Source too large")

    return data.decode("utf-8-sig", errors="replace")


def extract(text):
    # Источники могут содержать обычный текст или Base64.
    candidates = [text]
    compact = "".join(text.split())

    if compact and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        try:
            decoded = base64.b64decode(
                compact + "=" * (-len(compact) % 4),
                validate=False,
            ).decode("utf-8")
            candidates.append(decoded)
        except (ValueError, UnicodeError):
            pass

    for item in candidates:
        for token in re.findall(
            r"vless://[^\s<>\"']+",
            item,
            re.IGNORECASE,
        ):
            yield token.rstrip("),.;")


def valid(uri):
    try:
        parsed = urlsplit(uri)

        if (
            parsed.scheme.lower() != "vless"
            or not parsed.hostname
            or not parsed.port
            or not parsed.username
        ):
            return False

        query = {
            key.lower(): values
            for key, values in parse_qs(parsed.query).items()
        }

        security = query.get("security", [""])[0].lower()

        if security != "reality":
            return False

        if not (
            query.get("pbk")
            or query.get("publickey")
        ):
            return False

        if not (
            query.get("sni")
            or query.get("servername")
        ):
            return False

        return True

    except (ValueError, TypeError):
        return False


def main():
    found = {}
    source_status = []

    for source in SOURCES:
        try:
            entries = [
                uri for uri in extract(fetch(source))
                if valid(uri)
            ]

            for uri in entries:
                # Убираем дубликаты, даже если различаются названия.
                found.setdefault(uri.split("#", 1)[0], uri)

            source_status.append({
                "source": source,
                "parsed": len(entries),
                "ok": True,
            })

        except Exception as error:
            print("Source failed:", source, str(error)[:150])

            source_status.append({
                "source": source,
                "ok": False,
                "error": str(error)[:150],
            })

    os.makedirs("public", exist_ok=True)
    subscription_path = "public/sub.txt"

    if found:
        with open(subscription_path, "w", encoding="utf-8") as file:
            file.write("\n".join(found.values()) + "\n")

    elif not os.path.isfile(subscription_path):
        # Не выдаём пустой список за рабочую подписку.
        with open(subscription_path, "w", encoding="utf-8") as file:
            file.write("")

    with open(subscription_path, encoding="utf-8") as file:
        count = sum(
            1 for line in file
            if line.startswith("vless://")
        )

    status = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "count": count,
        "sources": source_status,
        "note": (
            "Configuration syntax checked only; "
            "live connectivity not tested."
        ),
    }

    with open("public/status.json", "w", encoding="utf-8") as file:
        json.dump(status, file, ensure_ascii=False, indent=2)

    print("Published", count, "configurations")


if __name__ == "__main__":
    main()
