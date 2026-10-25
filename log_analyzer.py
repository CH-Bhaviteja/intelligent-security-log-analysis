
import pandas as pd
from pathlib import Path

# Load the synthetic authentication log file
LOG_FILE = Path(__file__).with_name("sample_auth_logs.csv")
df = pd.read_csv(LOG_FILE)

# Count total events
print("\n=== SECURITY LOG ANALYZER ===")
print("Total events:", len(df))

# Summarize login events
print("\n=== EVENT SUMMARY ===")
print(df["event_type"].value_counts().to_string())

# Count failed logins for each username and source IP
failed = df[df["event_type"] == "LOGIN_FAILURE"]

failed_counts = (
    failed.groupby(["username", "source_ip"])
    .size()
    .reset_index(name="failed_attempts")
)

print("\n=== FAILED LOGIN COUNTS ===")
print(failed_counts.to_string(index=False))

# Generate alerts when failures reach 3 or more
alerts = failed_counts[
    failed_counts["failed_attempts"] >= 3
].copy()

alerts["severity"] = "MEDIUM"
alerts["reason"] = "Repeated failed login attempts"

print("\n=== SUSPICIOUS LOGIN ALERTS ===")

if alerts.empty:
    print("No suspicious login patterns detected.")
else:
    print(alerts.to_string(index=False))

# Check for successful logins after repeated failures
print("\n=== SUCCESS AFTER REPEATED FAILURES ===")

success_events = df[df["event_type"] == "LOGIN_SUCCESS"]
found = False

for _, alert in alerts.iterrows():
    matching_success = success_events[
        (success_events["username"] == alert["username"])
        & (success_events["source_ip"] == alert["source_ip"])
        & (success_events["timestamp"] > df[
            (df["username"] == alert["username"])
            & (df["source_ip"] == alert["source_ip"])
            & (df["event_type"] == "LOGIN_FAILURE")
        ]["timestamp"].max())
    ]

    if not matching_success.empty:
        print(
            f"Investigate: {alert['username']} from "
            f"{alert['source_ip']} had repeated failures "
            "followed by a successful login."
        )
        found = True

if not found:
    print("No matching sequence found.")

# Detect usernames outside the expected demo user list
print("\n=== UNKNOWN USER DETECTION ===")

known_users = {"alice", "bob", "charlie"}
unknown_events = df[~df["username"].isin(known_users)]

if unknown_events.empty:
    print("No unknown usernames found.")
else:
    print(
        unknown_events[
            ["timestamp", "username", "source_ip", "event_type"]
        ].to_string(index=False)
    )

# Export repeated-failure alerts to a CSV report
report_file = Path(__file__).with_name("security_alerts.csv")
alerts.to_csv(report_file, index=False)

print(f"\nAlert report saved to: {report_file.name}")
print("Total repeated-failure alerts:", len(alerts))

