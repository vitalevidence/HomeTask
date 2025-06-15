#!/bin/bash
set -x
PORT=1010101
IN_FILE=test_file
OUT_PATH=/tmp/1/
OUT_FILE=received_file

dd if=/dev/urandom of=${IN_FILE} bs=1M count=5 iflag=fullblock

mkdir ${OUT_PATH}

./stx_recv --listen ${PORT} --out ${OUT_PATH} &

# Save the PID of the background process
PROCESS_PID=$!
#echo $! > process.pid

srcHASH=$(sha256sum -b ${IN_FILE} | cut -f 1 -d " ")

./stx_send 127.0.0.1 ${PORT} ${IN_FILE} ${OUT_FILE}
# Optional: print the PID
#echo "Process started with PID: $(cat process.pid)"

# Send Ctrl-C (SIGINT) to the background process
kill -SIGINT $PROCESS_PID

dstHASH=$(sha256sum -b ${OUT_PATH}${OUT_FILE} | cut -f 1 -d " ")

if [ "$srcHASH" == "$dstHASH" ]; then
    echo "File transfer successful and hashes match."
    exit 0
else
    echo "File transfer failed or hashes do not match."
    echo "Source hash: $srcHASH"
    echo "Destination hash: $dstHASH"
    exit 1
fi
