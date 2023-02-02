from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.packet import Packet
import time
from flow import Flow


def create_flow_entry(pkt: Packet):
    new_flow = Flow()

    new_flow.flow_start = time.time()
    new_flow.flow_cur_time = time.time()

    new_flow.ip_addr_src = pkt[IP].src
    new_flow.ip_addr_dst = pkt[IP].dst
    new_flow.ip_port_src = pkt.sport
    new_flow.ip_port_dst = pkt.dport
    if pkt.haslayer(TCP):
        new_flow.ip_proto = 'TCP'
    elif pkt.haslayer(UDP):
        new_flow.ip_proto = 'UDP'
    elif pkt.haslayer(ICMP): # NOT IMPLEMENTED
        new_flow.ip_proto = 'ICMP'

    new_flow.ip_fwd_pkt_tot_num = 1
    new_flow.ip_fwd_pkt_tot_len = int(pkt[IP].len)
    new_flow.ip_fwd_pkt_len_max = int(pkt[IP].len)
    new_flow.ip_fwd_pkt_len_min = int(pkt[IP].len)
    new_flow.ip_fwd_pkt_len_mean = float(pkt[IP].len)
    new_flow.ip_fwd_pkt_len_std = 0.0

    new_flow.ip_pkt_tot_num = 1
    new_flow.ip_pkt_tot_len = int(pkt[IP].len)
    new_flow.ip_pkt_len_max = int(pkt[IP].len)
    new_flow.ip_pkt_len_min = int(pkt[IP].len)
    new_flow.ip_pkt_len_mean = float(pkt[IP].len)
    new_flow.ip_pkt_len_std = 0.0

    """
    TCP/IP FLAGS
    """
    if pkt.haslayer(TCP):
        if 'U' in pkt[TCP].flags:
            new_flow.tcp_fwd_urg_flags += 1
            new_flow.tcp_urg_flag_count += 1

        if 'P' in pkt[TCP].flags:
            new_flow.tcp_fwd_psh_flags += 1
            new_flow.tcp_psh_flag_count += 1

        if 'F' in pkt[TCP].flags:
            new_flow.tcp_fin_flag_count += 1
        if 'S' in pkt[TCP].flags:
            new_flow.tcp_syn_flag_count += 1
        if 'R' in pkt[TCP].flags:
            new_flow.tcp_rst_flag_count += 1
        if 'A' in pkt[TCP].flags:
            new_flow.tcp_ack_flag_count += 1
        if 'C' in pkt[TCP].flags:
            new_flow.tcp_cwr_flag_count += 1
        if 'E' in pkt[TCP].flags:
            new_flow.tcp_ece_flag_count += 1

    """
    TCP/IP MISC
    """
    if pkt[IP].frag == 1:
        new_flow.ip_dont_frag_count += 1

    if pkt[IP].ttl > 0:
        new_flow.ip_ttl_max = int(pkt[IP].ttl)
        new_flow.ip_ttl_min = int(pkt[IP].ttl)
        new_flow.ip_ttl_mean = float(pkt[IP].ttl)
        new_flow.ip_ttl_std = 0.0

        new_flow.ip_fwd_ttl_max = int(pkt[IP].ttl)
        new_flow.ip_fwd_ttl_min = int(pkt[IP].ttl)
        new_flow.ip_fwd_ttl_mean = float(pkt[IP].ttl)
        new_flow.ip_fwd_ttl_std = 0.0

    return new_flow


def update_flow_entry(flow: Flow, pkt: Packet, direction: int):  # dir 1 = fwd, 2 = bwd
    updated_flow = flow
    updated_flow.flow_cur_time = time.time()

    updated_flow.ip_pkt_tot_num += 1
    updated_flow.ip_pkt_tot_len += int(pkt[IP].len)
    if int(pkt[IP].len) > updated_flow.ip_pkt_len_max:
        updated_flow.ip_pkt_len_max = int(pkt[IP].len)
    if int(pkt[IP].len) < updated_flow.ip_pkt_len_min:
        updated_flow.ip_pkt_len_min = int(pkt[IP].len)

    # Rolling avg update
    oldavg = updated_flow.ip_pkt_len_mean
    updated_flow.ip_pkt_len_mean = oldavg + (int(pkt[IP].len) - oldavg) / updated_flow.ip_pkt_tot_num

    oldstd = updated_flow.ip_pkt_len_std
    updated_flow.ip_pkt_len_std = oldstd + (
                abs(int(pkt[IP].len) - oldavg) - oldstd) / updated_flow.ip_pkt_tot_num
    # curAvg = curAvg + (newNum - curAvg)/n;
    # calculate new std avg using ^ with old std, new dev, n

    """
    FWD FLOW FEATURES
    """
    if direction == 1:
        updated_flow.ip_fwd_pkt_tot_num += 1
        updated_flow.ip_fwd_pkt_tot_len += int(pkt[IP].len)
        if int(pkt[IP].len) > updated_flow.ip_fwd_pkt_len_max:
            updated_flow.ip_fwd_pkt_len_max = int(pkt[IP].len)
        if int(pkt[IP].len) < updated_flow.ip_fwd_pkt_len_min:
            updated_flow.ip_fwd_pkt_len_min = int(pkt[IP].len)

        # Rolling avg update
        oldavg = updated_flow.ip_fwd_pkt_len_mean
        updated_flow.ip_fwd_pkt_len_mean = oldavg + (
                    int(pkt[IP].len) - oldavg) / updated_flow.ip_fwd_pkt_tot_num

        oldstd = updated_flow.ip_fwd_pkt_len_std
        updated_flow.ip_fwd_pkt_len_std = oldstd + (
                    abs(int(pkt[IP].len) - oldavg) - oldstd) / updated_flow.ip_fwd_pkt_tot_num
        # curAvg = curAvg + (newNum - curAvg)/n;
        # calculate new std avg using ^ with old std, new dev, n

    """
    BWD FLOW FEATURES
    """

    if direction == 2:
        if updated_flow.ip_bwd_pkt_tot_num == 0:  # first backward packet
            updated_flow.ip_bwd_pkt_tot_num = 1
            updated_flow.ip_bwd_pkt_tot_len = int(pkt[IP].len)
            updated_flow.ip_bwd_pkt_len_max = int(pkt[IP].len)
            updated_flow.ip_bwd_pkt_len_min = int(pkt[IP].len)
            updated_flow.ip_bwd_pkt_len_mean = float(pkt[IP].len)
            updated_flow.ip_bwd_pkt_len_std = 0.0
        else:
            updated_flow.ip_bwd_pkt_tot_num += 1
            updated_flow.ip_bwd_pkt_tot_len += int(pkt[IP].len)
            if int(pkt[IP].len) > updated_flow.ip_bwd_pkt_len_max:
                updated_flow.ip_bwd_pkt_len_max = int(pkt[IP].len)
            if int(pkt[IP].len) < updated_flow.ip_bwd_pkt_len_min:
                updated_flow.ip_bwd_pkt_len_min = int(pkt[IP].len)

            # Rolling avg update
            oldavg = updated_flow.ip_bwd_pkt_len_mean
            updated_flow.ip_bwd_pkt_len_mean = oldavg + (
                        int(pkt[IP].len) - oldavg) / updated_flow.ip_bwd_pkt_tot_num

            oldstd = updated_flow.ip_bwd_pkt_len_std
            updated_flow.ip_bwd_pkt_len_std = oldstd + (
                        abs(int(pkt[IP].len) - oldavg) - oldstd) / updated_flow.ip_bwd_pkt_tot_num
            # curAvg = curAvg + (newNum - curAvg)/n;
            # calculate new std avg using ^ with old std, new dev, n

    """
    TCP/IP FLAGS
    """

    if pkt.haslayer(TCP):
        if 'U' in pkt[TCP].flags:
            if direction == 1:
                updated_flow.tcp_fwd_urg_flags += 1
            elif direction == 2:
                updated_flow.tcp_bwd_urg_flags += 1
            updated_flow.tcp_urg_flag_count += 1

        if 'P' in pkt[TCP].flags:
            if direction == 1:
                updated_flow.tcp_fwd_psh_flags += 1
            elif direction == 2:
                updated_flow.tcp_bwd_psh_flags += 1
            updated_flow.tcp_psh_flag_count += 1

        if 'F' in pkt[TCP].flags:
            updated_flow.tcp_fin_flag_count += 1
        if 'S' in pkt[TCP].flags:
            updated_flow.tcp_syn_flag_count += 1
        if 'R' in pkt[TCP].flags:
            updated_flow.tcp_rst_flag_count += 1
        if 'A' in pkt[TCP].flags:
            updated_flow.tcp_ack_flag_count += 1
        if 'C' in pkt[TCP].flags:
            updated_flow.tcp_cwr_flag_count += 1
        if 'E' in pkt[TCP].flags:
            updated_flow.tcp_ece_flag_count += 1

    """
    TCP/IP MISC
    """
    if pkt[IP].frag == 1:
        updated_flow.ip_dont_frag_count += 1

    if int(pkt[IP].ttl) > updated_flow.ip_ttl_max:
        updated_flow.ip_ttl_max = int(pkt[IP].ttl)
    if int(pkt[IP].ttl) < updated_flow.ip_ttl_min:
        updated_flow.ip_ttl_min = int(pkt[IP].ttl)
    oldavg = updated_flow.ip_ttl_mean
    updated_flow.ip_ttl_mean = oldavg + (int(pkt[IP].ttl) - oldavg) / updated_flow.ip_pkt_tot_num
    oldstd = updated_flow.ip_ttl_std
    updated_flow.ip_ttl_std = oldstd + (abs(int(pkt[IP].ttl) - oldavg) - oldstd) / updated_flow.ip_pkt_tot_num

    """
    TCP/IP FWD MISC
    """

    if direction == 1:
        if int(pkt[IP].ttl) > updated_flow.ip_fwd_ttl_max:
            updated_flow.ip_fwd_ttl_max = int(pkt[IP].ttl)
        if int(pkt[IP].ttl) < updated_flow.ip_fwd_ttl_min:
            updated_flow.ip_fwd_ttl_min = int(pkt[IP].ttl)
        oldavg = updated_flow.ip_fwd_ttl_mean
        updated_flow.ip_fwd_ttl_mean = oldavg + (int(pkt[IP].ttl) - oldavg) / updated_flow.ip_fwd_pkt_tot_num
        oldstd = updated_flow.ip_fwd_ttl_std
        updated_flow.ip_fwd_ttl_std = oldstd + (
                abs(int(pkt[IP].ttl) - oldavg) - oldstd) / updated_flow.ip_fwd_pkt_tot_num

        if updated_flow.ip_fwd_pkt_tot_num == 3 and updated_flow.ip_proto == 'TCP':  # s -> s/a -> data
            updated_flow.tcp_fwd_init_win = int(pkt[TCP].window)

    """
    TCP/IP BWD MISC
    """
    if direction == 2:
        if updated_flow.ip_bwd_pkt_tot_num == 1:  # first backward packet
            if int(pkt[IP].ttl) > 0:
                updated_flow.ip_bwd_ttl_max = int(pkt[IP].ttl)
                updated_flow.ip_bwd_ttl_min = int(pkt[IP].ttl)
                updated_flow.ip_bwd_ttl_mean = float(pkt[IP].ttl)
                updated_flow.ip_bwd_ttl_std = 0.0

        else:
            if int(pkt[IP].ttl) > updated_flow.ip_bwd_ttl_max:
                updated_flow.ip_bwd_ttl_max = int(pkt[IP].ttl)
            if int(pkt[IP].ttl) < updated_flow.ip_bwd_ttl_min:
                updated_flow.ip_bwd_ttl_min = int(pkt[IP].ttl)
            oldavg = updated_flow.ip_bwd_ttl_mean
            updated_flow.ip_bwd_ttl_mean = oldavg + (int(pkt[IP].ttl) - oldavg) / updated_flow.ip_bwd_pkt_tot_num
            oldstd = updated_flow.ip_bwd_ttl_std
            updated_flow.ip_bwd_ttl_std = oldstd + (
                        abs(int(pkt[IP].ttl) - oldavg) - oldstd) / updated_flow.ip_bwd_pkt_tot_num

        if updated_flow.ip_bwd_pkt_tot_num == 2 and updated_flow.ip_proto == 'TCP':  # s/a -> data
            updated_flow.tcp_bwd_init_win = int(pkt[TCP].window)

    return updated_flow


def flow_cleanup(flow: Flow):
    final_flow = flow
    try:
        final_flow.ip_flow_bytes_sec = final_flow.ip_pkt_tot_len / final_flow.ip_all_flow_duration
        final_flow.ip_flow_pkts_sec = final_flow.ip_pkt_tot_num / final_flow.ip_all_flow_duration

        final_flow.ip_fwd_pkts_sec = final_flow.ip_fwd_pkt_tot_num / final_flow.ip_all_flow_duration
        final_flow.ip_fwd_bytes_sec = final_flow.ip_fwd_pkt_tot_len / final_flow.ip_all_flow_duration


        final_flow.ip_bwd_pkts_sec = final_flow.ip_bwd_pkt_tot_num / final_flow.ip_all_flow_duration
        final_flow.ip_bwd_bytes_sec = final_flow.ip_bwd_pkt_tot_len / final_flow.ip_all_flow_duration

    except (ValueError, ZeroDivisionError):
        final_flow.ip_flow_bytes_sec = final_flow.ip_pkt_tot_len
        final_flow.ip_flow_pkts_sec = final_flow.ip_pkt_tot_num

        final_flow.ip_fwd_pkts_sec = final_flow.ip_fwd_pkt_tot_num
        final_flow.ip_fwd_bytes_sec = final_flow.ip_fwd_pkt_tot_len


        final_flow.ip_bwd_pkts_sec = final_flow.ip_bwd_pkt_tot_num
        final_flow.ip_bwd_bytes_sec = final_flow.ip_bwd_pkt_tot_len


    return final_flow
