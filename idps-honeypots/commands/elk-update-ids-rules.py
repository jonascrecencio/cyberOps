#!/usr/bin/env python3
# _*_ coding: utf-8 _*_

from datetime import datetime
from elasticsearch import Elasticsearch
import os
import pprint

pp = pprint.PrettyPrinter(width=41, compact=True)

ELASTIC_SEARCH_URL = 'https://3.231.208.103:64297/es/'
ELASTIC_SEARCH_USER = 'webuser'
ELASTIC_SEARCH_PASS = 'LINUX@4ever'
ELASTIC_SEARCH_DOC_LIMIT = 10000
SNORT_HP_RULES_SID_CFG = '/stor/docker/snort3/volumes/rules/honeypots/hp-sid.cfg'
SNORT_HP_RULES_START_SID = 3000001

def update_snort_rule_next_sid(path,rule_sid):
    with open(path, "w") as config:
        config.write(str(rule_sid))
    return

def get_snort_rule_start_sid(path):
    if os.path.isfile(path):
        with open(path) as config:
            start_sid = int(config.read())
    else:
        start_sid = SNORT_HP_RULES_START_SID
    return start_sid

def build_snort_rules(events,start_sid):
    snort_rules = []
    rule_sid = start_sid
    for event in events:
        tcp_rule = 'alert tcp {0} any -> {1} {2}(msg: "Detected by Honeypot" ; sid:{3})'.format(event['src_ip'], event['dest_ip'], event['dest_port'], rule_sid)
        snort_rules.append(tcp_rule)
        rule_sid = rule_sid + 1
        udp_rule = 'alert udp {0} any -> {1} {2}(msg: "Detected by Honeypot" ; sid:{3})'.format(event['src_ip'], event['dest_ip'], event['dest_port'], rule_sid)
        snort_rules.append(udp_rule)
        rule_sid = rule_sid + 1
    update_snort_rule_next_sid(SNORT_HP_RULES_SID_CFG,rule_sid)
    return snort_rules

def search_security_events():
    es = Elasticsearch(
        [ELASTIC_SEARCH_URL],
        http_auth=(ELASTIC_SEARCH_USER, ELASTIC_SEARCH_PASS),
        verify_certs=False,
    )

    res = es.search(
        index="logstash*",
        body={
            "size": ELASTIC_SEARCH_DOC_LIMIT,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1h"
                    }
                }
            },
            "collapse": {
                "field": "src_ip.keyword"
            }
        },
    )

    hits = res['hits']['hits']

    secEvents = []
    for event in hits:
        try:
            secEvent = {
                'src_ip': event['_source']['src_ip'],
                'dest_ip': event['_source']['dest_ip'],
                'dest_port': event['_source']['dest_port']
            }
            if secEvent not in secEvents:
                secEvents.append(secEvent)
        except:
            continue
    return secEvents

def main():
    snort_start_sid = get_snort_rule_start_sid(SNORT_HP_RULES_SID_CFG)
    secEvents = search_security_events()
    snort_rules = build_snort_rules(secEvents,snort_start_sid)
    for rule in snort_rules:
        print(rule)

if __name__ == "__main__":
    main()