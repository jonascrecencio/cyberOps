#!/usr/bin/env python3
# _*_ coding: utf-8 _*_

from datetime import datetime
from elasticsearch import Elasticsearch
import pprint

pp = pprint.PrettyPrinter(width=41, compact=True)


def main():
    es = Elasticsearch(
        ['https://3.231.208.103:64297/es/'],
        http_auth=('webuser', 'LINUX@4ever'),
        verify_certs=False,
    )

    res = es.search(
        index="logstash*",
        body={
            "size": 100,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": "now-1h"
                    }
                }
            }
        },
        scroll = '1m'
    )        

    hits = res['hits']['hits']
    scroll_id = res['_scroll_id']
    doc_count = res['hits']['total']['value']
    
    while doc_count > 0:
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
        doc_count = doc_count - 100
        res = es.scroll(
            scroll_id=scroll_id,
            scroll = '1m'
        )
        hits = res['hits']['hits']
        scroll_id = res['_scroll_id']

    pp.pprint(secEvents)

if __name__ == "__main__":
    main()