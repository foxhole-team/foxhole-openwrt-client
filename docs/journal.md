# Diagnostic journal

The FoxHole journal is enabled only when the package is installed in FLASH. It is disabled for a full RAM installation; the interface explains this instead of starting log collectors.

FLASH retains limited, sanitized diagnostic observations for up to 30 days from their first observation. The buffer is circular: new records replace the oldest when its budget is reached. Its size adapts to free space, is capped at 1 MiB and at 2% of the available space including the journal's reusable allocation, and leaves a system reserve of at least 1 MiB or 10% of the filesystem. Reduced free space shortens the retained history instead of pausing a full buffer. Rotation touches only the journal and its bounded temporary file.

The journal is collected periodically; the display can be refreshed manually. It contains selected tunnel-exit and memory-pressure events, not all errors or traffic history. Credentials, profile configurations and raw process command lines are not stored. Record timestamps identify the first observation; original kernel uptime is shown separately.

