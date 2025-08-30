#!/bin/bash
# Make executable with: chmod +x capture_traffic.sh

INTERFACE="Wi-Fi"  # Change this to your interface (use `tshark -D` to list)
DURATION=60        # Capture duration in seconds
OUTPUT="data/raw/traffic_$(date +%Y%m%d_%H%M%S).pcap"

echo "Capturing traffic for $DURATION seconds..."
tshark -i "$INTERFACE" -a duration:"$DURATION" -w "$OUTPUT"
echo "Capture complete. Saved to $OUTPUT"
