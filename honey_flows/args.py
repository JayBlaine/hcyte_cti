import argparse


def parse_args():
    parser = argparse.ArgumentParser(description="", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--interface", type=str, required=True,
                        default="eno1", help="Interface to listen to")
    parser.add_argument("-t", "--timeout", type=int, required=False,
                        default=60, help="How long after a packet until flow is inactive")
    parser.add_argument("-s", "--stop", type=int, required=False,
                        default=86400, help="How long to capture for")
    parser.add_argument("-r", "--read", type=str, required=False,
                        default="/mnt/captures/snort_internal/alert",
                        help="path to alert file to be read from. (Snort fast alert)")
    parser.add_argument("-w", "--write", type=str, required=False,
                        help="path to write csv file")
    return parser.parse_args()
