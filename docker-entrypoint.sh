#!/bin/bash
# IOC Harvester - Docker Entrypoint
# Translates Docker env vars into CLI arguments and runs the harvester.

set -e

echo "
╔══════════════════════════════════╗
║       IOC HARVESTER v1.0         ║
║  Threat Intelligence Aggregator  ║
╚══════════════════════════════════╝
"

# If the first argument is a known command, run it directly
if [[ "$1" == "run" || "$1" == "init" || "$1" == "sources" ]]; then
    exec ioc-harvester "$@"
fi

# Otherwise, run with output directory set
exec ioc-harvester run \
    --output-dir /app/output \
    ${LOG_LEVEL:+--log-level "$LOG_LEVEL"} \
    "$@"
