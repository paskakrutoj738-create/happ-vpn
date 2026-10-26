
import os
import json
import socket
import time
import base64
import urllib.request
import urllib.parse
import subprocess
import tempfile
import shutil
from datetime import datetime, timezone

OUTPUT_DIR = "public"
SUB_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
STATUS_FILE = os.path.join(OUTPUT_DIR, "status.json")

SUBSCRIPTION_NAME = "Quick VPN"
MAX_CANDIDATES_TO_TEST = 30
MAX_SERVERS = 5

TCP_TIMEOUT = 2.0
VPN_TEST_TIMEOUT = 12
SOCKS_PORT = 10808
XRAY_PATH = os.environ.get("XRAY_PATH", "xray")

TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

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
        headers={"User-Agent": "Quick-VPN-Collector/2.0"}
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

        if not parsed.hostname or not parsed.port or not parsed.username:
            return None

        if query.get("security", [""])[0].lower() != "reality":
            return None

        public_key = query.get(
            "pbk", query.get("publickey", [""])
        )[0]

        server_name = query.get(
            "sni", query.get("servername", [""])
        )[0]

        fingerprint = query.get("fp", ["chrome"])[0]
        short_id = query.get("sid", [""])[0]
        network = query.get("type", ["tcp"])[0].lower()
        flow = query.get("flow", [""])[0]

        if not public_key or not server_name:
            return None

        return {
            "uri": uri,
            "host": parsed.hostname,
            "port": parsed.port,
            "uuid": urllib.parse.unquote(parsed.username),
            "public_key": public_key,
            "server_name": server_name,
            "fingerprint": fingerprint,
            "short_id": short_id,
            "network": network,
            "flow": flow,
            "query": query,
        }

    except (ValueError, IndexError):
        return None


def measure_tcp(server):
    start = time.perf_counter()

    try:
        with socket.create_connection(
            (server["host"], server["port"]),
            timeout=TCP_TIMEOUT
        ):
            return (time.perf_counter() - start) * 1000
    except OSError:
        return None


def build_xray_config(server):
    query = server["query"]

    user = {
        "id": server["uuid"],
        "encryption": "none"
    }

    if server["flow"]:
        user["flow"] = server["flow"]

    outbound = {
        "tag": "vpn",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server["host"],
                "port": server["port"],
                "users": [user]
            }]
        },
        "streamSettings": {
            "network": server["network"],
            "security": "reality",
            "realitySettings": {
                "serverName": server["server_name"],
                "fingerprint": server["fingerprint"],
                "publicKey": server["public_key"],
                "shortId": server["short_id"],
                "spiderX": query.get("spx", ["/"])[0]
            }
        }
    }

    network = server["network"]

    if network == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "path": query.get("path", ["/"])[0],
            "headers": {
                "Host": query.get("host", [""])[0]
            }
        }

    elif network == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": query.get("serviceName", [""])[0]
        }

    elif network not in ("tcp", "raw"):
        raise ValueError("Unsupported network: " + network)

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": SOCKS_PORT,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": False
            }
        }],
        "outbounds": [
            outbound,
            {
                "tag": "blocked",
                "protocol": "blackhole"
            }
        ],
        "routing": {
            "rules": [{
                "type": "field",
                "ip": ["geoip:private"],
                "outboundTag": "blocked"
            }]
        }
    }


def test_vpn(server):
    if not shutil.which(XRAY_PATH):
        print("Xray не найден; полноценная проверка пропущена.")
        return None

    config = None
    process = None

    try:
        config = build_xray_config(server)

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            encoding="utf-8",
            delete=False
        ) as file:
            json.dump(config, file)
            config_path = file.name

        process = subprocess.Popen(
            [XRAY_PATH, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Ждём запуска локального SOCKS-прокси.
        ready = False
        for _ in range(20):
            if process.poll() is not None:
                break

            try:
                with socket.create_connection(
                    ("127.0.0.1", SOCKS_PORT),
                    timeout=0.3
                ):
                    ready = True
                    break
            except OSError:
                time.sleep(0.25)

        if not ready:
            return None

        result = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--socks5-hostname",
                f"127.0.0.1:{SOCKS_PORT}",
                "--connect-timeout", "5",
                "--max-time", str(VPN_TEST_TIMEOUT),
                TEST_URL
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=VPN_TEST_TIMEOUT + 3
        )

        if result.returncode != 0:
            return None

        # Проверяем, что получили ответ через прокси.
        if "ip=" not in result.stdout:
            return None

        return True

    except Exception as error:
        print(f"Ошибка проверки VPN: {str(error)[:120]}")
        return None

    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        if "config_path" in locals():
            try:
                os.remove(config_path)
            except OSError:
                pass


def rename_server(uri, name):
    parsed = urllib.parse.urlsplit(uri)
    fragment = urllib.parse.quote(name, safe=" -().")

    return urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.query,
        fragment
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
                server = parse_reality(uri)

                if server:
                    candidates.append(server)

        except Exception as error:
            errors.append({
                "source": source,
                "error": str(error)[:200]
            })

    # Сначала отбрасываем серверы с недоступным TCP-портом.
    reachable = []

    for server in candidates:
        latency = measure_tcp(server)

        if latency is not None:
            server["tcp_latency_ms"] = round(latency, 1)
            reachable.append(server)

        if len(reachable) >= MAX_CANDIDATES_TO_TEST:
            break

    reachable.sort(key=lambda server: server["tcp_latency_ms"])

    # Затем проверяем настоящий запрос через Xray.
    working = []
    xray_available = shutil.which(XRAY_PATH) is not None

    if xray_available:
        for server in reachable:
            if test_vpn(server):
                working.append(server)

                print(
                    "VPN работает:",
                    server["host"],
                    server["tcp_latency_ms"],
                    "ms"
                )

            if len(working) >= MAX_SERVERS:
                break

    # Без Xray не публикуем узлы как заведомо рабочие.
    selected = working if xray_available else []

    lines = [
        "#profile-title: Quick VPN",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
    ]

    for index, server in enumerate(selected):
        if index == 0:
            name = "Автовыбор"
        else:
            name = f"Запасной {index}"

        lines.append(rename_server(server["uri"], name))

    with open(SUB_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    status = {
        "name": SUBSCRIPTION_NAME,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "candidates_found": len(candidates),
        "tcp_reachable": len(reachable),
        "vpn_tested": len(reachable) if xray_available else 0,
        "servers_published": len(selected),
        "validation": (
            "xray_proxy_request"
            if xray_available
            else "not_tested_xray_missing"
        ),
        "servers": [
            {
                "name": "Автовыбор" if i == 0 else f"Запасной {i}",
                "tcp_latency_ms": server["tcp_latency_ms"]
            }
            for i, server in enumerate(selected)
        ],
        "source_errors": errors
    }

    with open(STATUS_FILE, "w", encoding="utf-8") as file:
        json.dump(status, file, ensure_ascii=False, indent=2)

    print("Найдено кандидатов:", len(candidates))
    print("TCP доступно:", len(reachable))
    print("Опубликовано проверенных VPN:", len(selected))


if __name__ == "__main__":
    main()
