# Copyright (c) 2017. Zuercher Hochschule fuer Angewandte Wissenschaften
#  All Rights Reserved.
#
#     Licensed under the Apache License, Version 2.0 (the "License"); you may
#     not use this file except in compliance with the License. You may obtain
#     a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#     WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#     License for the specific language governing permissions and limitations
#     under the License.

################################################################################
# OpenDaylight exporter for Prometheus: Scrapes metrics from OpenDaylight monitoring module.
# These metrics are exposed via the OpenFlow plugin statistics Collector APIs:
# https://wiki.opendaylight.org/view/OpenDaylight_OpenFlow_Plugin:Statistics
# This exporter is based on the Jenkins Prometheus exporters:
# https://www.robustperception.io/writing-a-jenkins-exporter-in-python/
# https://github.com/lovoo/jenkins_exporter
################################################################################

#!/usr/bin/python
__author__ = 'traj'

import json
import re
import sys
import time
import argparse
import requests
from requests.exceptions import ConnectionError
import os

try:
  import urllib2
except:
  #Python 3
  import urllib.request as urllib2

from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY

pattern = re.compile("[a-zA-Z_:]([a-zA-Z0-9_:])*")

class OpenDaylightCollector(object):
  def __init__(self, target, odl_inventory_url):
    self._target = target.rstrip("/")
    self._odl_inventory_url = odl_inventory_url
    #  ODL-related hosts that are exporting data.
    self.hosts_dict = {}

    inventory = requests.get(self._odl_inventory_url)
    if inventory:
        hosts_data = json.loads(inventory.content).get("nodes").get("node")
        if hosts_data:
            for host in hosts_data:
                ip_addr = host.get("flow-node-inventory:ip-address")
                host_name = self._ip_to_host_name_mapping(ip_addr)
                self.hosts_dict[host_name] = host.get("id")

  # Maps IP to host name for all OpenDaylight-related nodes to monitor
  def _ip_to_host_name_mapping(self, ip):
      return {
          '127.0.0.1': 'odl',
      }.get(ip, 'default_node')

  def _setup_new_metrics(self):

    # Metrics to export from OpenDaylight operational data store.
    self._metrics_host = {}

    self._metrics_port = {}

    self._metrics_flow = {}

    # Metric format odl_[metric_name]{instance="exporter_node",job="opendaylight",node_label="hostname_openflowid"}
    # metric_name eg: packet_count, bytes_received
    # host_name eg: odl, compute, control, neutron
    # Example metric: odl_active_flows{instance="160.85.4.121:9118",job="opendaylight",node_label="odl_openflow_1"}

    self._metrics_host = {
    'byte-count':
    GaugeMetricFamily('odl_byte_count',
        'OpenDaylight byte count per node', labels=["node_label"]),
    'flow-count':
    GaugeMetricFamily('odl_flow_count',
        'OpenDaylight flow count per node', labels=["node_label"]),
    'packet-count':
    GaugeMetricFamily('odl_packet_count',
        'OpenDaylight packet count per node', labels=["node_label"]),
    'active-flows':
    GaugeMetricFamily('odl_active_flows',
        'OpenDaylight active flows per node', labels=["node_label"]),
    'packets-lookedup':
    GaugeMetricFamily('odl_packets_looked_up',
        'OpenDaylight packets lookedup per node', labels=["node_label"]),
    'packets-matched':
    GaugeMetricFamily('odl_packets_matched',
        'OpenDaylight packets matched per node', labels=["node_label"])
    }

    # Example metric for port 2(s1-eth2): odl_packets_received_odl_s1_eth2_2
    self._metrics_port = {
    'packets-received':
    GaugeMetricFamily('odl_packets_received',
        'OpenDaylight packets received per node and per port', labels=["node", "port"]),
    'packets-transmitted':
    GaugeMetricFamily('odl_packets_transmitted',
        'OpenDaylight packets transmitted per node and per port', labels=["node", "port"]),
    'bytes-received':
    GaugeMetricFamily('odl_bytes_received',
        'OpenDaylight bytes received per node and per port', labels=["node", "port"]),
    'bytes-transmitted':
    GaugeMetricFamily('odl_bytes_transmitted',
        'OpenDaylight bytes transmitted per node and per port', labels=["node", "port"])
    }

    # Example metric for flow L2switch-1: odl_flow_packet_count_odl_l2switch_1
    self._metrics_flow = {
    'flow-duration':
    GaugeMetricFamily('odl_flow_duration',
        'OpenDaylight flow duration per node', labels=["node", "flow"]),
    'flow-packet-count':
    GaugeMetricFamily('odl_flow_packet_count',
        'OpenDaylight flow packet count per node', labels=["node", "flow"]),
    'flow-byte-count':
    GaugeMetricFamily('odl_flow_byte_count',
        'OpenDaylight flow byte count per node', labels=["node", "flow"]),
    }

  def _request_odl_data(self, host, node_connector_list, flow_statistics_list):

    # Data to export from OpenDaylight.
    data_dict = {}

    try:
        # Flow table statistics per host (eg. opendaylight, compute, control and neutron)
        try:
            table_flow_statistics_url = "%s%s%s%s" % (self._odl_inventory_url,'/node/',self.hosts_dict[host],'/table/0/opendaylight-flow-table-statistics:flow-table-statistics')
            table_flow_statistics = requests.get(table_flow_statistics_url)
            table_flow_statistics.raise_for_status()
            data_dict["table_flow_statistics"] = table_flow_statistics
        except requests.exceptions.HTTPError as err:
            print "Can not retrieve flow table statistics:", err
        # Aggregate flow statistics per host (eg. opendaylight, compute, control and neutron)
        try:
            aggregate_flow_statistics_url = "%s%s%s%s" % (self._odl_inventory_url,'/node/',self.hosts_dict[host],'/table/0/aggregate-flow-statistics/')
            aggregate_flow_statistics = requests.get(aggregate_flow_statistics_url)
            aggregate_flow_statistics.raise_for_status()
            data_dict["aggregate_flow_statistics"] = aggregate_flow_statistics
        except requests.exceptions.HTTPError as err:
            pass
            #print "Can not retrieve aggregate flow statistics:", err

        # Individual flow statistics per host (eg. opendaylight, compute, control and neutron)
        data_dict["flow_statistics_list"] = flow_statistics_list

        # Port statistics per host (eg. opendaylight, compute, control and neutron)
        data_dict["node_connector_list"] = node_connector_list

        return data_dict

    except ConnectionError:
        print("Error fetching data from OpenDaylight.")

  def _add_data_prometheus(self, data_dict, host, ports_list, flows_list):

    openflow_id = self.hosts_dict[host].replace(":", "_")
    host_label = '%s_%s' % (host, openflow_id)

    self._labels_list = {}
    self._labels_list["host_label"] = host_label
    self._labels_list["host"] = host

    try:
        # Flow table statistics per host

        table_flow_statistics = json.loads(data_dict["table_flow_statistics"].content).get("opendaylight-flow-table-statistics:flow-table-statistics")
        self._metrics_host['active-flows'].add_metric([self._labels_list["host_label"]], table_flow_statistics.get("active-flows"))
        self._metrics_host['packets-lookedup'].add_metric([self._labels_list["host_label"]], table_flow_statistics.get("packets-looked-up"))
        self._metrics_host['packets-matched'].add_metric([self._labels_list["host_label"]], table_flow_statistics.get("packets-matched"))
    except ConnectionError:
        print "OpenDaylight flow table statistics can not be retrieved."

    try:
        # Aggregate flow statistics per host
        if "aggregate_flow_statistics" in data_dict:
            aggregate_flow_statistics = json.loads(data_dict["aggregate_flow_statistics"].content).get("opendaylight-flow-statistics:aggregate-flow-statistics")
            self._metrics_host['byte-count'].add_metric([self._labels_list["host_label"]], aggregate_flow_statistics.get("byte-count"))
            self._metrics_host['flow-count'].add_metric([self._labels_list["host_label"]], aggregate_flow_statistics.get("flow-count"))
            self._metrics_host['packet-count'].add_metric('packet-count', aggregate_flow_statistics.get("packet-count"))
    except ConnectionError:
        print "OpenDaylight aggregate flow statistics can not be retrieved."

    try:
        # Individual flow statistics per host
        for key, value in data_dict["flow_statistics_list"].items():
            flows = []
            if key == "flow":
                for i in range(0, len(value)):
                    if value[i].get("opendaylight-flow-statistics:flow-statistics") is not None:
                        for index in range(0, len(flows_list)):
                            # Match can be based on for eg: priority (Netfloc SFC flows priority=20)
                            if value[i].get('priority') == 2:
                                flows.append(value[i].get("opendaylight-flow-statistics:flow-statistics"))
                                flow_duration = flows[index].get("duration").get("second")
                                flow_packet_count = flows[index].get("packet-count")
                                flow_byte_count = flows[index].get("byte-count")

                                self._metrics_flow['flow-duration'].add_metric([self._labels_list["host"], flows_list[index]], flow_duration)
                                self._metrics_flow['flow-packet-count'].add_metric([self._labels_list["host"], flows_list[index]], flow_packet_count)
                                self._metrics_flow['flow-byte-count'].add_metric([self._labels_list["host"], flows_list[index]], flow_byte_count)

    except ConnectionError:
        print "OpenDaylight flow statistics can not be retrieved."

    try:
        # Port statistics per host (eg. opendaylight,  compute, control and neutron)
        for key, value in data_dict["node_connector_list"].items():
            if "node-connector" in key:
                for i in range(0, len(value)):
                    if value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics") is not None:
                        packets_received = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("packets").get("received")
                        packets_transmitted = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("packets").get("transmitted")
                        bytes_received = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("bytes").get("received")
                        bytes_transmitted = value[i].get("opendaylight-port-statistics:flow-capable-node-connector-statistics").get("bytes").get("received")

                        self._metrics_port['packets-received'].add_metric([self._labels_list["host"], ports_list[i]], packets_received)
                        self._metrics_port['packets-transmitted'].add_metric([self._labels_list["host"], ports_list[i]], packets_transmitted)
                        self._metrics_port['bytes-received'].add_metric([self._labels_list["host"], ports_list[i]], bytes_received)
                        self._metrics_port['bytes-transmitted'].add_metric([self._labels_list["host"], ports_list[i]], bytes_transmitted)
    except ConnectionError:
        print "OpenDaylight port statistics can not be retrieved."

  def collect(self):

    try:

        self._setup_new_metrics()

        for host in self.hosts_dict:

            ports_list = []
            flows_list = []

            try:
                node_connector_url = "%s%s%s" % (self._odl_inventory_url,'/node/',self.hosts_dict[host])
                node_connector = requests.get(node_connector_url)
                try:
                    node_connector_list = json.loads(node_connector.content).get("node")[0]

                    # Iterate ports list
                    for key, value in node_connector_list.items():
                        if "node-connector" in key:
                            for i in range(0, len(value)):
                                port_name = re.sub(r'[^\w]', '_', str(value[i].get("flow-node-inventory:name")).lower())
                                port_number = value[i].get("flow-node-inventory:port-number")
                                if pattern.match(port_name):
                                    ports_list.append("%s%s%s" % (port_name,'_',str(port_number)))

                except (ValueError, TypeError) as error:
                    print "ODL is still starting...", error

                flow_statistics_url =  "%s%s%s%s" % (self._odl_inventory_url,'/node/',self.hosts_dict[host],'/table/0/')
                flow_statistics = requests.get(flow_statistics_url)
                try:
                    flow_statistics_list = json.loads(flow_statistics.content).get('flow-node-inventory:table')[0]

                # Iterate flows list to filter the IDs of specific flows (eg. priority=2)
                # Flow ID format: l2switch_1
                    for key, value in flow_statistics_list.items():
                        if key == "flow":
                            for i in range(0, len(value)):
                                if value[i].get('priority') == 2 and not re.search('UF',value[i].get('id')):
                                    flow_id = re.sub(r'[^\w]', '_', str(value[i].get('id')).lower())
                                    if pattern.match(flow_id):
                                        flows_list.append(flow_id)


                    data_dict = self._request_odl_data(host, node_connector_list, flow_statistics_list)
                    self._add_data_prometheus(data_dict, host, ports_list, flows_list)

                except  (ValueError, TypeError) as error:
                    print "ODL is still starting...", error

            except ConnectionError:
                print "OpenDaylight flow and port statistics can not be retrieved. Is ODL running?"

        for metric_host in self._metrics_host.values():
            yield metric_host


        for metric_port in self._metrics_port.values():
            yield metric_port


        for metric_flow in self._metrics_flow.values():
            yield metric_flow

    except ConnectionError:
        print "OpenDaylight metrics can not be retrieved and displayed."

def parse_args():
    parser = argparse.ArgumentParser(
        description='OpenDaylight exporter args - OpenDaylight address, inventory and port'
    )
    parser.add_argument(
        '-o', '--opendaylight',
        metavar='opendaylight',
        required=False,
        help='OpenDaylight url',
        default=os.environ.get('ODL_NODE', 'http://odl_url:8181')
    )
    parser.add_argument(
        '-i', '--odl_inventory',
        metavar='odl_inventory',
        required=False,
        help='OpenDaylight inventory url',
        default=os.environ.get('ODL_INVENTORY', 'http://admin:admin@odl_url:8181/restconf/operational/opendaylight-inventory:nodes')
    )
    parser.add_argument(
        '-p', '--port',
        metavar='port',
        required=False,
        type=int,
        help='The exporter listens to this port',
        default=int(os.environ.get('VIRTUAL_PORT', '9118'))
    )
    return parser.parse_args()

def main():
    try:
        args = parse_args()
        port = int(args.port)
        while True:
            try:
                if requests.get(args.odl_inventory):
                    REGISTRY.register(OpenDaylightCollector(args.opendaylight, args.odl_inventory))
                    start_http_server(port)
                    print "Polling data from OpenDaylight: %s. Starting OpenDaylight exporter on port: %s" % (args.opendaylight, port)
                    while True:
                        time.sleep(1)
            except ConnectionError:
                print "OpenDaylight is either not running or it is unreachable."
    except KeyboardInterrupt:
        print(" Interrupted")
        exit(0)

if __name__ == "__main__":
    main()
