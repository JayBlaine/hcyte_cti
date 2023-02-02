from flow_tracker import FlowTracker
from follow import follow


def main():
    t = FlowTracker(iface='eth0', stop=86400, timeout=90)
    print(t.filename)

    t.sniffer.start()

    alert_file = open('/mnt/captures/snort_internal/alert', "r")
    alert_lines = follow(alert_file, t)

    for line in alert_lines:
        line_list = line.split()
        src = line_list[-3:][0]
        dst = line_list[-1:][0]
        try:
            t.flows["{} {}".format(src, dst)].label = 1
            t.flows["{} {}".format(src, dst)].flow_alert = line
        except KeyError:
            try:
                t.flows["{} {}".format(dst, src)].label = 1
                t.flows["{} {}".format(src, dst)].flow_alert = line
            except KeyError:
                # Key error: Some snort rules (port sweep) don't have port number -> can't find reliably
                continue


    # GET IP SRC IP DST FROM LINE, ----> t.flows[src:sport dst:dport].label=1
    t.sniffer.stop()


if __name__ == "__main__":
    main()
