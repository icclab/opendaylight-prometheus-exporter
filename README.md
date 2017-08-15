## OpenDaylight exporter for Prometheus

This is exporter for [OpenDaylight](https://github.com/opendaylight). Shows data from the operational datastore of OpenDaylight inventory. The metrics are retrieved from OpenDaylight OpenFlow plugin statistics Collector APIs.
The exporter bases on the example of the [Jenkins exporters]
(https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
https://github.com/lovoo/jenkins_exporter).

### Installation

```
git clone git@github.com:icclab/opendaylight-prometheus-exporter
```
### Setup

Extend the prometheus.yml file in your Prometheus endpoint, with configuration as in the following example:

```
scrape_configs:
  # The job name is added as a label `job=<job_name>` to any timeseries scraped from this config.
  - job_name: 'opendaylight'
    scrape_interval: 2s
    # metrics_path defaults to '/metrics'
    # scheme defaults to 'http'.

    static_configs:
      - targets: ['[odl_prometheus_exporter_node_url:port]']
```

In Grafana setup the Prometheus service URL as data source endpoint. The metrics can be queried using "odl" as prefix. Example metric in Grafana:

```
odl_bytes_received_[node]_s1_eth2_2{instance="160.85.4.121:9118",job="opendaylight",odl_s1_eth2_2="b"}
```


### Usage

```
usage: opendaylight-prometheus-exporter.py [-h] [-o opendaylight]
                                           [-i odl_inventory] [-p port]

OpenDaylight exporter args - OpenDaylight address, inventory and port

optional arguments:
  -h, --help            show this help message and exit
  -o opendaylight, --opendaylight opendaylight
                        OpenDaylight url
  -i odl_inventory, --odl_inventory odl_inventory
                        OpenDaylight inventory url
  -p port, --port port  The exporter listens to this port
```


