import datetime as dt
import time

from scapy.layers.inet import IP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
from scapy.sessions import IPSession

from flow_handler import create_flow_entry, update_flow_entry


class FlowTracker:
    filename: str = "flows_{}.csv".format(dt.datetime.now().strftime("%Y-%m-%d_%H-%M"))
    sniffer: AsyncSniffer = None
    flows: dict = {}
    # dict of Flows(cls)
    interface: str
    timeout: int = 60

    def __init__(self, iface: str, flows: dict = None, timeout: int = None):
        """
        Main handler for tracking flows from live capture

        :param iface: Interface to listen on
        :param flows: Dictionary of active flows
        :param timeout: Int for how long after a packet to call a flow inactive
        """
        if flows is not None:
            self.flows = flows
        if timeout is not None:
            self.timeout = timeout

        self.interface = iface

        self.sniffer = AsyncSniffer(iface=self.interface, session=IPSession,
                                    prn=prn_scapy(flows=self.flows, timeout=self.timeout),
                                    filter='ip and (tcp or udp) and (net 64.183.181.215 or net 192.168.50.0/24)')


def prn_scapy(flows: dict, timeout: int):
    """
    Wrapper for prn in sniffer to allow passing of arguments

    :param flows: Dictionary of active flows
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
                flows.pop(j)

    return read_pkt
