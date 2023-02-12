from flow_tracker import FlowTracker
import re


def main():
    t = FlowTracker(iface='eth0', timeout=90)

    t.sniffer.start()


    # GET IP SRC IP DST FROM LINE, ----> flow_sniffer.flows[src:sport dst:dport].label=1
    t.sniffer.stop()


if __name__ == "__main__":
    main()
