import time

from webApp.app import flow_sniffer


def follow(file):
    """
    Behaves like tail -f: follows file and returns new lines as they're appended
    :param file: followed file
    :return: yields lines as they're appended, continues execution.
    """
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line


def alert_follow():
    alert_file = open('/mnt/captures/snort_internal/alert', "r")
    alert_lines = follow(alert_file)

    for line in alert_lines:
        line_list = line.split()
        src = line_list[-3:][0]
        dst = line_list[-1:][0]
        try:
            flow_sniffer.flows["{} {}".format(src, dst)].label = 1
            flow_sniffer.flows["{} {}".format(src, dst)].flow_alert = re.split(r'\[\*\*]', line)[1]
        except KeyError:
            try:
                flow_sniffer.flows["{} {}".format(dst, src)].label = 1
                flow_sniffer.flows["{} {}".format(src, dst)].flow_alert = re.split(r'\[\*\*]', line)[1]
            except KeyError:
                # Key error: Some snort rules (port sweep) don'flow_sniffer have port number -> can'flow_sniffer find reliably
                continue