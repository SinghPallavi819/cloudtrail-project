import csv
import json
import os
from pathlib import Path
from urllib import request

# ✅ Put your CloudTrail JSON filename here
LOG_FILE = "293723385373_CloudTrail_us-east-1_20260127T0515Z_kZTp6fx1Ln2AsDzp.json"

# ✅ High-risk events you want to flag
HIGH_RISK_EVENTS = {
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutBucketPublicAccessBlock",
    "DeleteBucketPublicAccessBlock",
    "DisableKey",
    "ScheduleKeyDeletion",
}

OUTPUT_CSV = "high_risk_events.csv"


def load_env_file(env_path=".env"):
    """Loads simple KEY="VALUE" lines from .env into os.environ."""
    p = Path(env_path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        os.environ[key] = val


def slack_send(message: str):
    """Send a message to Slack via Incoming Webhook URL."""
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook:
        print("⚠️ SLACK_WEBHOOK_URL not set. Skipping Slack alert.")
        return

    payload = json.dumps({"text": message}).encode("utf-8")
    req = request.Request(
        webhook,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print("✅ Slack alert sent")
            else:
                print(f"⚠️ Slack returned status {resp.status}")
    except Exception as e:
        print(f"❌ Slack alert failed: {e}")


def get_user_type(user_identity: dict) -> str:
    if not user_identity:
        return "Unknown"
    return user_identity.get("type", "Unknown")


def get_user_arn(user_identity: dict) -> str:
    if not user_identity:
        return "Unknown"
    return user_identity.get("arn") or user_identity.get("principalId") or "Unknown"


def main():
    load_env_file(".env")

    path = Path(LOG_FILE)
    if not path.exists():
        print(f"❌ File not found: {path.resolve()}")
        return

    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("Records", [])

    print(f"Loaded {len(records)} CloudTrail events")

    flagged = []
    for r in records:
        event_name = r.get("eventName", "Unknown")
        event_source = r.get("eventSource", "Unknown")
        event_time = r.get("eventTime", "Unknown")
        read_only = r.get("readOnly", False)
        user_identity = r.get("userIdentity", {})
        user_type = get_user_type(user_identity)
        user_arn = get_user_arn(user_identity)
        src_ip = r.get("sourceIPAddress", "Unknown")

        # Flag high-risk only when it's NOT read-only OR it's a known risky action
        if event_name in HIGH_RISK_EVENTS and read_only is False:
            flagged.append(
                {
                    "eventTime": event_time,
                    "eventSource": event_source,
                    "eventName": event_name,
                    "readOnly": read_only,
                    "userType": user_type,
                    "userArn": user_arn,
                    "sourceIPAddress": src_ip,
                }
            )

    print(f"✅ Flagged {len(flagged)} high-risk events")

    # Write CSV
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "eventTime",
                "eventSource",
                "eventName",
                "readOnly",
                "userType",
                "userArn",
                "sourceIPAddress",
            ],
        )
        writer.writeheader()
        writer.writerows(flagged)

    print(f"📄 Saved report: {OUTPUT_CSV}")

    # Send Slack alert if anything flagged
    if flagged:
        # Send only first 5 events to avoid spam
        top = flagged[:5]
        lines = ["🚨 *High-Risk AWS Events Detected (CloudTrail)*"]
        for e in top:
            lines.append(
                f"• `{e['eventName']}` by `{e['userType']}` | user `{e['userArn']}` | IP `{e['sourceIPAddress']}` | `{e['eventTime']}`"
            )
        if len(flagged) > 5:
            lines.append(f"…and {len(flagged) - 5} more. See `{OUTPUT_CSV}` for full report.")
        slack_send("\n".join(lines))
    else:
        print("ℹ️ No Slack alert (no high-risk events).")


if __name__ == "__main__":
    main()

