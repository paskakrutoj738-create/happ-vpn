
import os
import json
import socket
import time
import base64
import urllib.request
import urllib.parse
from datetime import datetime, timezone

OUTPUT_DIR = "public"
SUB_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
STATUS_FILE = os.path.join(OUTPUT_DIR, "status.json")

SUBSCRIPTION_NAME = "Quick VPN"
MAX_CANDIDATES_TO_TEST = 100
MAX_SERVERS = 10
TCP_TIMEOUT = 2.0

SOURCES = [
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/reality.txt"
]

extra_sources = os.environ.get("EXTRA_SOURCES", "").strip()
if extra_sources:
    SOURCES.extend(
        line.strip()
        for line in extra_sources.splitlines()
        if line.strip()
    )


def fetch(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Quick-VPN-Collector/1.0"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read(8_000_000).decode("utf-8", "ignore")


def extract_uris(text):
    text = text.strip()

    if "vless://" not in text:
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


def parse_reality(uri):
    try:
        parsed = urllib.parse.urlsplit(uri)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.scheme != "vless":
            return None

        if not parsed.hostname or not parsed.port:
            return None

        if not parsed.username:
            return None

        if query.get("security", [""])[0].lower() != "reality":
            return None

        public_key = query.get(
            "pbk", query.get("publickey", [""])
        )[0]
        server_name = query.get(
            "sni", query.get("servername", [""])
        )[0]

        if not public_key or not server_name:
            return None

        return parsed.hostname, parsed.port

    except (ValueError, IndexError):
        return None


def measure_tcp(uri):
    endpoint = parse_reality(uri)
    if not endpoint:
        return None

    host, port = endpoint
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port), timeout=TCP_TIMEOUT
        ):
            return (time.perf_counter() - start) * 1000
    except OSError:
        return None


def rename_server(uri, index, latency):
    parsed = urllib.parse.urlsplit(uri)
    label = f"Quick VPN {index:02d} ({latency:.0f} ms)"

    return urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        urllib.parse.quote(label, safe=" -().")
    ))


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    candidates = []
    seen = set()
    errors = []

    for source in SOURCES:
        try:
            for uri in extract_uris(fetch(source)):
                if uri in seen:
                    continue
                seen.add(uri)

                if parse_reality(uri):
                    candidates.append(uri)

        except Exception as error:
            errors.append({
                "source": source,
                "error": str(error)[:200]
            })

    # Ограничиваем число проверок, чтобы workflow не зависал надолго.
    candidates_to_test = candidates[:MAX_CANDIDATES_TO_TEST]
    tested = []

    print(f"Всего найдено: {len(candidates)}")
    print(f"Будет проверено максимум: {len(candidates_to_test)}")

    for index, uri in enumerate(candidates_to_test, start=1):
        latency = measure_tcp(uri)

        if latency is not None:
            tested.append((latency, uri))

        if index % 10 == 0:
            print(f"Проверено: {index}/{len(candidates_to_test)}")

    tested.sort(key=lambda item: item[0])
    selected = tested[:MAX_SERVERS]

    lines = [
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#profile-title: Quick VPN",
    ]

    for index, (latency, uri) in enumerate(selected, start=1):
        lines.append(rename_server(uri, index, latency))

    with open(SUB_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    status = {
        "name": SUBSCRIPTION_NAME,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "candidates_found": len(candidates),
        "candidates_checked": len(candidates_to_test),
        "servers_tested": len(tested),
        "servers_published": len(selected),
        "tcp_latency_ms": [
            round(latency, 1) for latency, _ in selected
        ],
        "validation": "tcp_check_only_not_vpn_handshake",
        "source_errors": errors
    }

    with open(STATUS_FILE, "w", encoding="utf-8") as file:
        json.dump(status, file, ensure_ascii=False, indent=2)

    print(f"Опубликовано серверов: {len(selected)}")

    if selected:
        print(f"Лучшая TCP-задержка: {selected[0][0]:.1f} ms")
    else:
        print("Нет серверов с доступным TCP-портом")


if __name__ == "__main__":
    main()
