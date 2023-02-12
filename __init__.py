import threading
from app import alert_follow, app, flow_sniffer

if __name__ == '__main__':
    try:
        # flow_sniffer.sniffer.start()
        follow_thread = threading.Thread(target=alert_follow, name="alert_follower")
        # follow_thread.start()
        app.run(port=80, debug=False)
    except KeyboardInterrupt:
        print('exiting')
        # flow_sniffer.sniffer.stop()