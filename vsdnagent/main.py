import argparse
import logging
import os
import subprocess

from vsdnagent import vsdnagent

import coloredlogs as coloredlogs

logger = logging.getLogger("vsdnagent")


def ryu_cmd(port):
    listen_port = "--ofp-tcp-listen-port"
    #agent_app = "/code/vsdnagent/vsdnagent/vsdnagent.py"
    cmd = ["ryu-manager", listen_port, port, vsdnagent]
    subprocess.call(cmd)


def main(port):
    if 'ORCH_ADDR' is not os.environ:
        os.environ['ORCH_ADDR'] = "ws://127.0.0.1:8080/ws"

    if 'ORCH_REALM' is not os.environ:
        os.environ['ORCH_REALM'] = 'realm1'

    if 'AGENT_PREFIX' is not os.environ:
        os.environ['AGENT_PREFIX'] = ""

    if 'ORCH_TRANS_BRIDGE' is not os.environ:
        os.environ['ORCH_TRANS_BRIDGE'] = "tswitch0"

    if 'OVS_ADDR' is not os.environ:
        os.environ['OVS_ADDR'] = "tcp:127.0.0.1:6640"

    ryu_cmd(port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=str)
    args = parser.parse_args()
    coloredlogs.install(logger=logger)
    logger.info("Starting vSDNAgent")

    if args.port is None:
        parser.print_help()
    else:
        try:
            main(args.port)
        except KeyboardInterrupt as ex:
            print("Exiting...")
