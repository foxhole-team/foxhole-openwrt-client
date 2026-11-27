# Diagnostic journal

The persistent FoxHole journal is available in FLASH. In RAM, the panel shows
up to ten recent VPN events from the current boot, including connection,
failed start, unexpected exit and stop. The panel reads these events from
temporary storage. Entries include the time and, when available, the engine
and exit status.

FLASH retains limited, sanitized diagnostic observations for up to 30 days from their first observation. The buffer is circular: new records replace the oldest when its budget is reached. Its size adapts to free space, is capped at 1 MiB and at 2% of the available space including the journal's reusable allocation, and leaves a system reserve of at least 1 MiB or 10% of the filesystem. Reduced free space shortens the retained history instead of pausing a full buffer. Rotation touches only the journal and its bounded temporary file.

The panel requests data on opening and refreshes every six seconds while
visible. Use the refresh button in the Journal header to reload it manually.
In FLASH, the collector records selected tunnel-exit and
memory-pressure events. Record timestamps identify the first observation,
with the original kernel uptime shown separately. Neither view stores
credentials, profile configurations, raw process command lines or traffic
history.

