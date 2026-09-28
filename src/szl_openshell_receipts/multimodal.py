import hashlib
import json


def bundle(parts):
    if not parts:
        raise ValueError("at least one channel is required")
    channels = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(parts.items())}
    combined = hashlib.sha256(json.dumps(channels, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"channels": channels, "combined_digest": combined, "channel_count": len(channels)}
