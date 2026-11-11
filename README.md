# India ransomware victim alerts

This poller requests `https://api.ransomware.live/v2/countryvictims/IN` every 90 seconds.
The URL can be changed with `RANSOMWARE_API_URL` if the upstream API changes.

## Files

- `india_victims.json` contains the most recent successful API response.
- `alert.json` contains only records newly seen in the latest successful refresh.
- `threat_actors.yaml` keeps cumulative `threat_actor`/`post_url` pairs.

Actor names are read from `group_name` (and compatible group fields). Post URLs are
trimmed after the `.onion` domain.

On the first successful run, the response becomes the baseline and `alert.json` is empty.
Failed requests do not overwrite any state files.

## Run

```powershell
python -m pip install -r requirements.txt
python randomware_alerts.py
```

Use `python randomware_alerts.py --once` for a single refresh. The interval and output
paths can also be configured with `RANSOMWARE_POLL_SECONDS`, `RANSOMWARE_*_FILE`, and
`RANSOMWARE_API_URL` environment variables.

If `india_victims.json` already contains data, sync its actor pairs with:

```powershell
python randomware_alerts.py --sync-actors
```
