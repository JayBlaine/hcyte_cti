import datetime as dt
import time
import csv

from scapy.layers.inet import IP
from scapy.packet import Packet
from scapy.sendrecv import sniff, AsyncSniffer
from scapy.sessions import IPSession

from flow import Flow
from flow_handler import create_flow_entry, update_flow_entry, flow_cleanup


class FlowTracker:
    filename: str = "flows_{}.csv".format(dt.datetime.now().strftime("%Y-%m-%d_%H-%M"))
    sniffer: AsyncSniffer = None
    flows: dict = {}
    # dict of Flows(cls)
    interface: str
    timeout: int = 60

    def __init__(self, iface: str, filename: str = None, flows: dict = None, timeout: int = None, stop: int = 90):
        """
        Main handler for tracking flows from live capture

        :param iface: Interface to listen on
        :param filename: CSV file to write completed flows to
        :param flows: Dictionary of active flows
        :param timeout: Int for how long after a packet to call a flow inactive
        :param stop: Int for how long the sniffer is active
        """
        if filename is not None:
            self.filename = filename
        if flows is not None:
            self.flows = flows
        if timeout is not None:
            self.timeout = timeout

        self.interface = iface

        with open(self.filename, 'w') as f:
            w_obj = csv.writer(f)
            w_obj.writerow(list(Flow.__dict__.keys())[3:63])
            f.close()

        # sniff(iface=interface, session=IPSession, prn=prn_scapy(flows=flows, writefile=filename), filter='ip and (tcp or udp)')
        self.sniffer = AsyncSniffer(iface=self.interface, session=IPSession,
                                    prn=prn_scapy(flows=self.flows, writefile=self.filename, timeout=self.timeout),
                                    filter='ip and (tcp or udp) and (net 64.183.181.215 or net 192.168.50.0/24)', timeout=stop)
                                                               
    def final_cleanup(self):
        """
        Call after sniffer stops to write open flows to csv

        """
        for j in self.flows.copy().keys():
            # flow over, write to csv, remove from dict
            self.flows[j].ip_all_flow_duration = self.flows[j].flow_cur_time - self.flows[j].flow_start
            # label=0 default
            self.flows[j] = flow_cleanup(flow=self.flows[j])
            # flow_buf.append(flows[j]._get_all()[:-1])
            with open(self.filename, 'a') as f:
                w_obj = csv.writer(f)
                w_obj.writerow(self.flows[j]._get_all())
                f.close()
            self.flows.pop(j)


def prn_scapy(flows: dict, writefile: str, timeout: int):
    """
    Wrapper for prn in sniffer to allow passing of arguments

    :param flows: Dictionary of active flows
    :param writefile: CSV to write finished flows to
    :param timeout: Int for how long after a packet to call a flow inactive
    :return: Function with pkt argument for prn in sniffer
    """
    def read_pkt(pkt: Packet):
        flowid = "{}:{} {}:{}".format(pkt[IP].src, pkt.sport, pkt[IP].dst, pkt.dport)  # key for self.flows dict
        flowid_rev = "{}:{} {}:{}".format(pkt[IP].dst, pkt.dport, pkt[IP].src, pkt.sport)
        # print(flows)
        if flowid in flows.keys():  # fwd
            flows[flowid] = update_flow_entry(flow=flows[flowid], pkt=pkt, direction=1)

        elif flowid_rev in flows.keys():  # bwd
            flows[flowid_rev] = update_flow_entry(flow=flows[flowid_rev], pkt=pkt, direction=2)

        else:
            flows[flowid] = create_flow_entry(pkt=pkt)

        cur_time = time.time()
        for j in flows.copy().keys():
            if cur_time - timeout > flows[j].flow_cur_time:
                # flow over, write to csv, remove from dict
                flows[j].ip_all_flow_duration = flows[j].flow_cur_time - flows[j].flow_start
                # label=0 default
                flows[j] = flow_cleanup(flow=flows[j])
                # flow_buf.append(flows[j]._get_all()[:-1])
                with open(writefile, 'a') as f:
                    w_obj = csv.writer(f)
                    w_obj.writerow(flows[j]._get_all())
                    f.close()
                flows.pop(j)

    return read_pkt
