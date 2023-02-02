from dataclasses import dataclass, fields


@dataclass
class Flow:
    """
    Flow test
    """
    ip_all_flow_duration: float = 0.0  # time
    flow_start: float = -1.0  # Non-features, for seeing when flow ends
    flow_cur_time: float = -1.0

    ip_addr_src: str = "0.0.0.0"
    ip_addr_dst: str = "0.0.0.0"
    ip_port_src: int = 0
    ip_port_dst: int = 0
    ip_proto: str = 'NA'  # 0: TCP 1: UDP 2: ICMP

    ip_fwd_pkt_tot_num: int = 0  # src -> dst
    ip_fwd_pkt_tot_len: int = 0
    ip_fwd_pkt_len_max: int = 0
    ip_fwd_pkt_len_min: int = 0
    ip_fwd_pkt_len_mean: float = 0.0
    ip_fwd_pkt_len_std: float = 0.0

    ip_fwd_pkts_sec: float = 0.0  # pkts/s and bytes/s at end with ip_all_flow_duration
    ip_fwd_bytes_sec: float = 0.0

    ip_bwd_pkt_tot_num: int = 0  # dst -> src
    ip_bwd_pkt_tot_len: int = 0
    ip_bwd_pkt_len_max: int = 0
    ip_bwd_pkt_len_min: int = 0
    ip_bwd_pkt_len_mean: float = 0.0
    ip_bwd_pkt_len_std: float = 0.0

    ip_bwd_pkts_sec: float = 0.0    # pkts/s and bytes/s at end with ip_all_flow_duration
    ip_bwd_bytes_sec: float = 0.0


    """
    Combined fwd/bwd
    """

    ip_pkt_tot_num: int = 0  # maybe redundant but in cicids???
    ip_pkt_tot_len: int = 0
    ip_pkt_len_max: int = 0
    ip_pkt_len_min: int = 0
    ip_pkt_len_mean: float = 0.0
    ip_pkt_len_std: float = 0.0

    ip_flow_bytes_sec: float = 0.0  # pkts/s and bytes/s at end with ip_all_flow_duration
    ip_flow_pkts_sec: float = 0.0

    # IAT (inter arrival time??)

    """
    TCP/IP FLAGS
    """
    ip_dont_frag_count: int = 0

    tcp_fwd_psh_flags: int = 0
    tcp_bwd_psh_flags: int = 0
    tcp_fwd_urg_flags: int = 0
    tcp_bwd_urg_flags: int = 0

    tcp_fin_flag_count: int = 0
    tcp_syn_flag_count: int = 0
    tcp_rst_flag_count: int = 0
    tcp_psh_flag_count: int = 0
    tcp_ack_flag_count: int = 0
    tcp_urg_flag_count: int = 0
    tcp_cwr_flag_count: int = 0
    tcp_ece_flag_count: int = 0

    """
    TCP/IP MISC
    """

    ip_ttl_max: int = 0
    ip_ttl_min: int = 0
    ip_ttl_mean: float = 0.0
    ip_ttl_std: float = 0.0

    ip_fwd_ttl_max: int = 0
    ip_fwd_ttl_min: int = 0
    ip_fwd_ttl_mean: float = 0.0
    ip_fwd_ttl_std: float = 0.0

    ip_bwd_ttl_max: int = 0
    ip_bwd_ttl_min: int = 0
    ip_bwd_ttl_mean: float = 0.0
    ip_bwd_ttl_std: float = 0.0

    tcp_fwd_init_win: int = -1
    tcp_bwd_init_win: int = -1
    # TCP header len???

    label: int = 0  # 0: benign   1: malicious

    def __str__(self):
        return "{}:{} -> {}:{}".format(self.ip_addr_src, self.ip_port_src, self.ip_addr_dst, self.ip_port_dst)

    def __repr__(self):
        return "debug here"

    @classmethod
    def _get_defaults(cls):
        return [f.default for f in fields(cls)]

    def _get_all(self):
        # return [value for name, value in vars(self).items()]
        return [getattr(self, f.name) for f in fields(self)]

