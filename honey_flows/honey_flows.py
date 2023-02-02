from flow_tracker import FlowTracker
from args import parse_args
from follow import follow

import sys


# TODO: argparse for hcyte usage


def main():
    args = parse_args()
    writefile = None
    if args.write is not None:
        writefile = args.write
    readfile = args.read

    t = FlowTracker(iface=args.interface, stop=args.stop, timeout=args.timeout, filename=writefile)
    print(t.filename)

    t.sniffer.start()

    alert_file = open(readfile, "r")
    alert_lines = follow(alert_file, t)

    for line in alert_lines:
        line_list = line.split()
        src = line_list[-3:][0]
        dst = line_list[-1:][0]
        try:
            t.flows["{} {}".format(src, dst)].label = 1
        except KeyError:
            try:
                t.flows["{} {}".format(dst, src)].label = 1
            except KeyError:
                # Key error: Some snort rules (port sweep) don't have port number -> can't find reliably
                continue





    # GET IP SRC IP DST FROM LINE, ----> t.flows[src:sport dst:dport].label=1
    t.sniffer.stop()
    t.final_cleanup()


if __name__ == "__main__":
    main()
