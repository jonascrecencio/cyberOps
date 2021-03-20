#!/bin/bash

SNORT_HP_RULE_DIR=/stor/docker/snort3/volumes/rules/honeypots
FILE_NAME="honeypot_`date +%Y-%m-%d-%I`.rules"

if [ -f /usr/bin/elk-update-ids-rules ]; then
  elk-update-ids-rules > $SNORT_HP_RULE_DIR/$FILE_NAME
  systemctl restart snort3
fi