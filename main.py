import logging
import sys
import os
import coloredlogs as coloredlogs
from ryu.cmd import manager

logger = logging.getLogger("vsdnagent")


def main():
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

    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6653')
    sys.argv.append('vsdnagent')
    #sys.argv.append('--verbose')
    # sys.argv.append('--enable-debugger')
    manager.main()


if __name__ == '__main__':
    main()
    coloredlogs.install(logger=logger)
    logger.info("Starting vSDNAgent")
