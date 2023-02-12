from flow import Flow

test_flows = {'142.251.45.74:443 192.168.50.46:44498': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3453438, flow_cur_time=1675385158.3470175, ip_addr_src='142.251.45.74', ip_addr_dst='192.168.50.46', ip_port_src=443, ip_port_dst=44498, ip_proto='TCP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=108, ip_fwd_pkt_len_max=108, ip_fwd_pkt_len_min=108, ip_fwd_pkt_len_mean=108.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=40, ip_bwd_pkt_len_max=40, ip_bwd_pkt_len_min=40, ip_bwd_pkt_len_mean=40.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=2, ip_pkt_tot_len=148, ip_pkt_len_max=108, ip_pkt_len_min=40, ip_pkt_len_mean=74.0, ip_pkt_len_std=34.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=1, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=1, tcp_syn_flag_count=0, tcp_rst_flag_count=1, tcp_psh_flag_count=1, tcp_ack_flag_count=1, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=121, ip_ttl_min=64, ip_ttl_mean=92.5, ip_ttl_std=28.5, ip_fwd_ttl_max=121, ip_fwd_ttl_min=121, ip_fwd_ttl_mean=121.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=64, ip_bwd_ttl_min=64, ip_bwd_ttl_mean=64.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=1, flow_alert="malicious flow"),
         '192.168.50.1:53 192.168.50.4:55251': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3487823, flow_cur_time=1675385158.348783, ip_addr_src='192.168.50.1', ip_addr_dst='192.168.50.4', ip_port_src=53, ip_port_dst=55251, ip_proto='UDP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=237, ip_fwd_pkt_len_max=237, ip_fwd_pkt_len_min=237, ip_fwd_pkt_len_mean=237.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=1, ip_pkt_tot_len=237, ip_pkt_len_max=237, ip_pkt_len_min=237, ip_pkt_len_mean=237.0, ip_pkt_len_std=0.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=64, ip_ttl_mean=64.0, ip_ttl_std=0.0, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.4:49291 52.92.197.34:443': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3504314, flow_cur_time=1675385158.425372, ip_addr_src='192.168.50.4', ip_addr_dst='52.92.197.34', ip_port_src=49291, ip_port_dst=443, ip_proto='TCP', ip_fwd_pkt_tot_num=2, ip_fwd_pkt_tot_len=100, ip_fwd_pkt_len_max=60, ip_fwd_pkt_len_min=40, ip_fwd_pkt_len_mean=50.0, ip_fwd_pkt_len_std=10.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=52, ip_bwd_pkt_len_max=52, ip_bwd_pkt_len_min=52, ip_bwd_pkt_len_mean=52.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=3, ip_pkt_tot_len=152, ip_pkt_len_max=60, ip_pkt_len_min=40, ip_pkt_len_mean=50.666666666666664, ip_pkt_len_std=8.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=2, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=2, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=39, ip_ttl_mean=55.666666666666664, ip_ttl_std=12.5, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=39, ip_bwd_ttl_min=39, ip_bwd_ttl_mean=39.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '52.218.168.161:443 192.168.50.4:54400': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3670692, flow_cur_time=1675385159.2781978, ip_addr_src='52.218.168.161', ip_addr_dst='192.168.50.4', ip_port_src=443, ip_port_dst=54400, ip_proto='TCP', ip_fwd_pkt_tot_num=332, ip_fwd_pkt_tot_len=928784, ip_fwd_pkt_len_max=7200, ip_fwd_pkt_len_min=56, ip_fwd_pkt_len_mean=2797.542168674698, ip_fwd_pkt_len_std=1430.7841287306749, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=62, ip_bwd_pkt_tot_len=2480, ip_bwd_pkt_len_max=40, ip_bwd_pkt_len_min=40, ip_bwd_pkt_len_mean=40.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=394, ip_pkt_tot_len=931264, ip_pkt_len_max=7200, ip_pkt_len_min=40, ip_pkt_len_mean=2363.6142131979714, ip_pkt_len_std=1570.634090460824, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=124, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=124, tcp_ack_flag_count=394, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=225, ip_ttl_min=64, ip_ttl_mean=199.6649746192895, ip_ttl_std=40.01305978770675, ip_fwd_ttl_max=225, ip_fwd_ttl_min=225, ip_fwd_ttl_mean=225.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=64, ip_bwd_ttl_min=64, ip_bwd_ttl_mean=64.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=251, tcp_bwd_init_win=6366, label=0, flow_alert="benign flow"),
         '5.92.178.194:443 192.168.50.4:39195': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3901327, flow_cur_time=1675385158.664594, ip_addr_src='52.92.178.194', ip_addr_dst='192.168.50.4', ip_port_src=443, ip_port_dst=39195, ip_proto='TCP', ip_fwd_pkt_tot_num=7, ip_fwd_pkt_tot_len=2642, ip_fwd_pkt_len_max=1853, ip_fwd_pkt_len_min=40, ip_fwd_pkt_len_mean=377.42857142857144, ip_fwd_pkt_len_std=422.7809523809524, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=7, ip_bwd_pkt_tot_len=802, ip_bwd_pkt_len_max=509, ip_bwd_pkt_len_min=40, ip_bwd_pkt_len_mean=114.57142857142857, ip_bwd_pkt_len_std=125.85476190476193, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=14, ip_pkt_tot_len=3444, ip_pkt_len_max=1853, ip_pkt_len_min=40, ip_pkt_len_mean=245.99999999999997, ip_pkt_len_std=295.1860116074402, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=5, tcp_bwd_psh_flags=2, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=1, tcp_syn_flag_count=0, tcp_rst_flag_count=1, tcp_psh_flag_count=7, tcp_ack_flag_count=14, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=225, ip_ttl_min=64, ip_ttl_mean=144.5, ip_ttl_std=75.15787407037408, ip_fwd_ttl_max=225, ip_fwd_ttl_min=225, ip_fwd_ttl_mean=225.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=64, ip_bwd_ttl_min=64, ip_bwd_ttl_mean=64.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=251, tcp_bwd_init_win=1822, label=0, flow_alert="benign flow"),
         '44.239.168.170:443 192.168.50.4:52927': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.393926, flow_cur_time=1675385158.3939264, ip_addr_src='44.239.168.170', ip_addr_dst='192.168.50.4', ip_port_src=443, ip_port_dst=52927, ip_proto='TCP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=52, ip_fwd_pkt_len_max=52, ip_fwd_pkt_len_min=52, ip_fwd_pkt_len_mean=52.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=1, ip_pkt_tot_len=52, ip_pkt_len_max=52, ip_pkt_len_min=52, ip_pkt_len_mean=52.0, ip_pkt_len_std=0.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=1, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=230, ip_ttl_min=230, ip_ttl_mean=230.0, ip_ttl_std=0.0, ip_fwd_ttl_max=230, ip_fwd_ttl_min=230, ip_fwd_ttl_mean=230.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.46:54958 216.58.193.138:443': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.3977053, flow_cur_time=1675385159.0446622, ip_addr_src='192.168.50.46', ip_addr_dst='216.58.193.138', ip_port_src=54958, ip_port_dst=443, ip_proto='TCP', ip_fwd_pkt_tot_num=15, ip_fwd_pkt_tot_len=16243, ip_fwd_pkt_len_max=1452, ip_fwd_pkt_len_min=52, ip_fwd_pkt_len_mean=1082.8666666666666, ip_fwd_pkt_len_std=506.6025074925074, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=15, ip_bwd_pkt_tot_len=819, ip_bwd_pkt_len_max=91, ip_bwd_pkt_len_min=52, ip_bwd_pkt_len_mean=54.60000000000001, ip_bwd_pkt_len_std=7.15406204906205, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=30, ip_pkt_tot_len=17062, ip_pkt_len_max=1452, ip_pkt_len_min=52, ip_pkt_len_mean=568.7333333333333, ip_pkt_len_std=574.3793563587185, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=4, tcp_bwd_psh_flags=1, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=5, tcp_ack_flag_count=30, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=57, ip_ttl_mean=60.50000000000001, ip_ttl_std=3.494055725158824, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=57, ip_bwd_ttl_min=57, ip_bwd_ttl_mean=57.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=1069, tcp_bwd_init_win=910, label=0, flow_alert="benign flow"),
         '192.168.50.81:28079 100.20.212.253:8886': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.413447, flow_cur_time=1675385158.6640112, ip_addr_src='192.168.50.81', ip_addr_dst='100.20.212.253', ip_port_src=28079, ip_port_dst=8886, ip_proto='TCP', ip_fwd_pkt_tot_num=2, ip_fwd_pkt_tot_len=149, ip_fwd_pkt_len_max=109, ip_fwd_pkt_len_min=40, ip_fwd_pkt_len_mean=74.5, ip_fwd_pkt_len_std=34.5, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=109, ip_bwd_pkt_len_max=109, ip_bwd_pkt_len_min=109, ip_bwd_pkt_len_mean=109.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=3, ip_pkt_tot_len=258, ip_pkt_len_max=109, ip_pkt_len_min=40, ip_pkt_len_mean=86.0, ip_pkt_len_std=23.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=1, tcp_bwd_psh_flags=1, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=2, tcp_ack_flag_count=3, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=255, ip_ttl_min=40, ip_ttl_mean=183.33333333333334, ip_ttl_std=107.5, ip_fwd_ttl_max=255, ip_fwd_ttl_min=255, ip_fwd_ttl_mean=255.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=40, ip_bwd_ttl_min=40, ip_bwd_ttl_mean=40.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.84:25980 100.20.212.253:8886': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.414956, flow_cur_time=1675385158.5890331, ip_addr_src='192.168.50.84', ip_addr_dst='100.20.212.253', ip_port_src=25980, ip_port_dst=8886, ip_proto='TCP', ip_fwd_pkt_tot_num=2, ip_fwd_pkt_tot_len=149, ip_fwd_pkt_len_max=109, ip_fwd_pkt_len_min=40, ip_fwd_pkt_len_mean=74.5, ip_fwd_pkt_len_std=34.5, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=109, ip_bwd_pkt_len_max=109, ip_bwd_pkt_len_min=109, ip_bwd_pkt_len_mean=109.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=3, ip_pkt_tot_len=258, ip_pkt_len_max=109, ip_pkt_len_min=40, ip_pkt_len_mean=86.0, ip_pkt_len_std=23.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=1, tcp_bwd_psh_flags=1, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=2, tcp_ack_flag_count=3, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=255, ip_ttl_min=40, ip_ttl_mean=183.33333333333334, ip_ttl_std=107.5, ip_fwd_ttl_max=255, ip_fwd_ttl_min=255, ip_fwd_ttl_mean=255.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=40, ip_bwd_ttl_min=40, ip_bwd_ttl_mean=40.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.12:5353 224.0.0.251:5353': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.7222493, flow_cur_time=1675385158.7222495, ip_addr_src='192.168.50.12', ip_addr_dst='224.0.0.251', ip_port_src=5353, ip_port_dst=5353, ip_proto='UDP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=721, ip_fwd_pkt_len_max=721, ip_fwd_pkt_len_min=721, ip_fwd_pkt_len_mean=721.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=1, ip_pkt_tot_len=721, ip_pkt_len_max=721, ip_pkt_len_min=721, ip_pkt_len_mean=721.0, ip_pkt_len_std=0.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=255, ip_ttl_min=255, ip_ttl_mean=255.0, ip_ttl_std=0.0, ip_fwd_ttl_max=255, ip_fwd_ttl_min=255, ip_fwd_ttl_mean=255.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.46:5353 224.0.0.251:5353': Flow(ip_all_flow_duration=0.0, flow_start=1675385158.826049, flow_cur_time=1675385158.845369, ip_addr_src='192.168.50.46', ip_addr_dst='224.0.0.251', ip_port_src=5353, ip_port_dst=5353, ip_proto='UDP', ip_fwd_pkt_tot_num=4, ip_fwd_pkt_tot_len=784, ip_fwd_pkt_len_max=406, ip_fwd_pkt_len_min=68, ip_fwd_pkt_len_mean=196.0, ip_fwd_pkt_len_std=142.08333333333334, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=4, ip_pkt_tot_len=784, ip_pkt_len_max=406, ip_pkt_len_min=68, ip_pkt_len_mean=196.0, ip_pkt_len_std=142.08333333333334, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=255, ip_ttl_min=255, ip_ttl_mean=255.0, ip_ttl_std=0.0, ip_fwd_ttl_max=255, ip_fwd_ttl_min=255, ip_fwd_ttl_mean=255.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=1, flow_alert="malicious Flow"),
         '192.168.50.12:59839 192.168.50.1:53': Flow(ip_all_flow_duration=0.0, flow_start=1675385159.1794949, flow_cur_time=1675385159.2324014, ip_addr_src='192.168.50.12', ip_addr_dst='192.168.50.1', ip_port_src=59839, ip_port_dst=53, ip_proto='UDP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=83, ip_fwd_pkt_len_max=83, ip_fwd_pkt_len_min=83, ip_fwd_pkt_len_mean=83.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=193, ip_bwd_pkt_len_max=193, ip_bwd_pkt_len_min=193, ip_bwd_pkt_len_mean=193.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=2, ip_pkt_tot_len=276, ip_pkt_len_max=193, ip_pkt_len_min=83, ip_pkt_len_mean=138.0, ip_pkt_len_std=55.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=64, ip_ttl_mean=64.0, ip_ttl_std=0.0, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=64, ip_bwd_ttl_min=64, ip_bwd_ttl_mean=64.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.12:2471 192.168.50.1:53': Flow(ip_all_flow_duration=0.0, flow_start=1675385159.181915, flow_cur_time=1675385159.2334096, ip_addr_src='192.168.50.12', ip_addr_dst='192.168.50.1', ip_port_src=2471, ip_port_dst=53, ip_proto='UDP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=83, ip_fwd_pkt_len_max=83, ip_fwd_pkt_len_min=83, ip_fwd_pkt_len_mean=83.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=1, ip_bwd_pkt_tot_len=193, ip_bwd_pkt_len_max=193, ip_bwd_pkt_len_min=193, ip_bwd_pkt_len_mean=193.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=2, ip_pkt_tot_len=276, ip_pkt_len_max=193, ip_pkt_len_min=83, ip_pkt_len_mean=138.0, ip_pkt_len_std=55.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=0, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=64, ip_ttl_mean=64.0, ip_ttl_std=0.0, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=64, ip_bwd_ttl_min=64, ip_bwd_ttl_mean=64.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.12:39444 54.191.114.159:443': Flow(ip_all_flow_duration=0.0, flow_start=1675385159.2389517, flow_cur_time=1675385159.2389524, ip_addr_src='192.168.50.12', ip_addr_dst='54.191.114.159', ip_port_src=39444, ip_port_dst=443, ip_proto='TCP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=60, ip_fwd_pkt_len_max=60, ip_fwd_pkt_len_min=60, ip_fwd_pkt_len_mean=60.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=1, ip_pkt_tot_len=60, ip_pkt_len_max=60, ip_pkt_len_min=60, ip_pkt_len_mean=60.0, ip_pkt_len_std=0.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=1, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=64, ip_ttl_mean=64.0, ip_ttl_std=0.0, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow"),
         '192.168.50.12:39446 54.191.114.159:443': Flow(ip_all_flow_duration=0.0, flow_start=1675385159.2404437, flow_cur_time=1675385159.2404444, ip_addr_src='192.168.50.12', ip_addr_dst='54.191.114.159', ip_port_src=39446, ip_port_dst=443, ip_proto='TCP', ip_fwd_pkt_tot_num=1, ip_fwd_pkt_tot_len=60, ip_fwd_pkt_len_max=60, ip_fwd_pkt_len_min=60, ip_fwd_pkt_len_mean=60.0, ip_fwd_pkt_len_std=0.0, ip_fwd_pkts_sec=0.0, ip_fwd_bytes_sec=0.0, ip_bwd_pkt_tot_num=0, ip_bwd_pkt_tot_len=0, ip_bwd_pkt_len_max=0, ip_bwd_pkt_len_min=0, ip_bwd_pkt_len_mean=0.0, ip_bwd_pkt_len_std=0.0, ip_bwd_pkts_sec=0.0, ip_bwd_bytes_sec=0.0, ip_pkt_tot_num=1, ip_pkt_tot_len=60, ip_pkt_len_max=60, ip_pkt_len_min=60, ip_pkt_len_mean=60.0, ip_pkt_len_std=0.0, ip_flow_bytes_sec=0.0, ip_flow_pkts_sec=0.0, ip_dont_frag_count=0, tcp_fwd_psh_flags=0, tcp_bwd_psh_flags=0, tcp_fwd_urg_flags=0, tcp_bwd_urg_flags=0, tcp_fin_flag_count=0, tcp_syn_flag_count=1, tcp_rst_flag_count=0, tcp_psh_flag_count=0, tcp_ack_flag_count=0, tcp_urg_flag_count=0, tcp_cwr_flag_count=0, tcp_ece_flag_count=0, ip_ttl_max=64, ip_ttl_min=64, ip_ttl_mean=64.0, ip_ttl_std=0.0, ip_fwd_ttl_max=64, ip_fwd_ttl_min=64, ip_fwd_ttl_mean=64.0, ip_fwd_ttl_std=0.0, ip_bwd_ttl_max=0, ip_bwd_ttl_min=0, ip_bwd_ttl_mean=0.0, ip_bwd_ttl_std=0.0, tcp_fwd_init_win=-1, tcp_bwd_init_win=-1, label=0, flow_alert="benign flow")}