"""Poll India's ransomware.live victims feed and persist changes."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

import requests
import yaml


API_URL = os.getenv(
    "RANSOMWARE_API_URL",
    "https://api.ransomware.live/v2/countryvictims/IN",
)
POLL_SECONDS = int(os.getenv("RANSOMWARE_POLL_SECONDS", "120"))
REQUEST_TIMEOUT = int(os.getenv("RANSOMWARE_REQUEST_TIMEOUT", "30"))
BASELINE_FILE = Path(os.getenv("RANSOMWARE_BASELINE_FILE", "india_victims.json"))
ALERT_FILE = Path(os.getenv("RANSOMWARE_ALERT_FILE", "alert.json"))
ACTORS_FILE = Path(os.getenv("RANSOMWARE_ACTORS_FILE", "threat_actors.yaml"))

LOGGER = logging.getLogger("ransomware-alerts")


def write_json(path: Path, value: Any) -> None:
    """Write JSON atomically so an interrupted refresh cannot corrupt state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        json.dump(value, temporary, indent=2, ensure_ascii=False)
        temporary.write("\n")
        temporary_path = Path(temporary.name)
    temporary_path.replace(path)


def write_yaml(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as temporary:
        yaml.safe_dump(value, temporary, sort_keys=False, allow_unicode=True)
        temporary_path = Path(temporary.name)
    temporary_path.replace(path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists() or path.stat().st_size == 0:
        return default
    try:
        with path.open(encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("Ignoring unreadable state file: %s", path)
        return default


def records_from_payload(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("victims"), list):
        return payload["victims"]
    if isinstance(payload, dict):
        return [payload]
    raise ValueError("API response must be a JSON object or array")


def record_key(record: Any) -> str:
    if isinstance(record, dict):
        for field in ("id", "uuid", "post_url", "url"):
            if record.get(field):
                return f"{field}:{record[field]}"
    encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_post_url(value: Any) -> str:
    """Keep only the URL through the .onion domain, when present."""
    text = str(value).strip()
    match = re.search(r"https?://[^\s\"']+?\.onion", text, flags=re.IGNORECASE)
    return match.group(0).rstrip(".,;)]}") if match else text


def extract_actor_url_pairs(records: list[Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        actor = next(
            (
                record.get(field)
                for field in ("threat_actor", "group_name", "group", "actor")
                if record.get(field)
            ),
            None,
        )
        post_url = next(
            (record.get(field) for field in ("post_url", "postUrl", "url") if record.get(field)),
            None,
        )
        if actor and post_url:
            pairs.add((str(actor), normalize_post_url(post_url)))
    return pairs


def load_actor_pairs() -> set[tuple[str, str]]:
    if not ACTORS_FILE.exists():
        return set()
    try:
        with ACTORS_FILE.open(encoding="utf-8") as file:
            document = yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError):
        LOGGER.warning("Ignoring unreadable actor state file: %s", ACTORS_FILE)
        return set()
    entries = document.get("threat_actors", []) if isinstance(document, dict) else []
    return {
        (str(entry["threat_actor"]), normalize_post_url(entry["post_url"]))
        for entry in entries
        if isinstance(entry, dict) and entry.get("threat_actor") and entry.get("post_url")
    }


def update_actor_pairs(records: list[Any]) -> None:
    pairs = load_actor_pairs() | extract_actor_url_pairs(records)
    document = {
        "threat_actors": [
            {"threat_actor": actor, "post_url": post_url}
            for actor, post_url in sorted(pairs, key=lambda pair: (pair[0].lower(), pair[1]))
        ]
    }
    write_yaml(ACTORS_FILE, document)


def refresh() -> bool:
    response = requests.get(
        API_URL,
        headers={"Accept": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    payload = response.json()
    current_records = records_from_payload(payload)

    previous_payload = load_json(BASELINE_FILE, None)
    if previous_payload is None:
        new_records = []
    else:
        previous_records = records_from_payload(previous_payload)
        previous_keys = {record_key(record) for record in previous_records}
        new_records = [
            record for record in current_records if record_key(record) not in previous_keys
        ]

    write_json(BASELINE_FILE, payload)
    write_json(ALERT_FILE, new_records)
    update_actor_pairs(current_records)
    LOGGER.info(
        "Refresh complete: %d records, %d new, baseline=%s, alerts=%s",
        len(current_records),
        len(new_records),
        BASELINE_FILE,
        ALERT_FILE,
    )
    return bool(new_records)


def sync_actors_from_baseline() -> None:
    payload = load_json(BASELINE_FILE, None)
    if payload is None:
        raise ValueError(f"No readable baseline found in {BASELINE_FILE}")
    update_actor_pairs(records_from_payload(payload))
    LOGGER.info("Synchronized actor pairs from %s into %s", BASELINE_FILE, ACTORS_FILE)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    parser.add_argument(
        "--sync-actors",
        action="store_true",
        help="rebuild threat actor pairs from the existing baseline without polling",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.sync_actors:
        sync_actors_from_baseline()
        return

    while True:
        try:
            refresh()
        except (requests.RequestException, ValueError, OSError, yaml.YAMLError) as error:
            LOGGER.error("Refresh failed; existing state was left unchanged: %s", error)
        if args.once:
            break
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
