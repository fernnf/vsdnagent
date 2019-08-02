import socket
import os
import uuid

from ryu.base.app_manager import RyuApp
from ryu.lib.ovs.vsctl import VSCtlCommand, VSCtl
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner
from autobahn import wamp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser


def check_ovs_service():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        result = sock.connect_ex(('127.0.0.1', 6640))
        if result == 0:
            return True
        else:
            return False


def run_command(ovsdb, cmd, args):
    command = VSCtlCommand(cmd, args)
    ovsdb.run_command([command])
    return command.result


def bridge_exist(ovsdb, bridge):
    return run_command(ovsdb, "br-exists", [bridge])


def get_ovsdb_attr(ovsdb, table, record, column, key=None):
    if key is not None:
        column = "{c}:{k}".format(c=column, k=key)

    return run_command(ovsdb, "get", [table, record, column])


def set_ovsdb_attr(ovsdb, table, record, column, value, key=None):
    if key is not None:
        column = "{c}:{k}".format(c=column, k=key)

    ret = run_command(ovsdb, "set", [table, record, "{c}={v}".format(c=column, v=value)])
    if ret is not None:
        raise ValueError(str(ret))


def get_dpid(ovsdb, bridge):
    return get_ovsdb_attr(ovsdb, "Bridge", bridge, "datapath_id")[0][0]


def set_dpid(ovsdb, bridge, dpid):
    ret = set_ovsdb_attr(ovsdb, "Bridge", bridge, "other_config", dpid, "datapath-id")
    if ret is not None:
        raise ValueError(str(ret))


def get_port(ovsdb, bridge, portnum):
    ports = run_command(ovsdb, 'list-ports', [bridge])
    if len(ports) == 0:
        raise ValueError("there is no ports on virtual bridge <{b}> ".format(b=bridge))
    for port in ports:
        pn = get_ovsdb_attr(ovsdb, 'Interface', port, "ofport")[0][0]
        if pn == int(portnum):
            type = get_ovsdb_attr(ovsdb, 'Interface', port, "type")[0][0]
            if type == 'patch':
                peer = get_ovsdb_attr(ovsdb, 'Interface', port, "options")[0]['peer']
                return port, peer
            return port, None
    return None, None


def set_bridge(ovsdb, label, datapath_id=None, protocols=None):
    def create():
        if not bridge_exist(ovsdb, label):
            ret = run_command(ovsdb, "add-br", [label])
            if ret is not None:
                raise ValueError(str(ret))
        else:
            raise ValueError("A virtual instance <{i}> with name already exists on node".format(i=label))

    def config():
        if datapath_id is not None:
            ret = set_ovsdb_attr(ovsdb, "Bridge", label, "other_config", datapath_id, "datapath-id")
            if ret is not None:
                raise ValueError(str(ret))

        if protocols is not None:
            assert (isinstance(protocols, list)), 'the protocols must be a list object'
            proto = ",".join(protocols)
            ret = set_ovsdb_attr(ovsdb, 'Bridge', label, 'protocols', proto)
            if ret is not None:
                raise ValueError(str(ret))

    if check_ovs_service():
        create()
        config()
        return get_dpid(ovsdb, label)
    else:
        raise ValueError("the ovsdb service is not available")


def del_bridge(ovsdb, label):
    if bridge_exist(ovsdb, label):
        ret = run_command(ovsdb, 'del-br', [label])
        if ret is not None:
            raise ValueError(str(ret))
    else:
        raise ValueError("the virtual instance <{i}> is not exist".format(i=label))


# TODO Change the try catch to check_ovs_service
def add_vport(ovsdb, instance, portnum=None):
    port = "V{i}".format(i=str(uuid.uuid4())[:8])
    peer = "R{i}".format(i=str(uuid.uuid4())[:8])
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def create(b, p):
        if bridge_exist(ovsdb, b):
            ret = run_command(ovsdb, 'add-port', [b, p])
            if ret is not None:
                raise ValueError(str(ret))

    def config_vport(v, p):
        r = set_ovsdb_attr(ovsdb, "Interface", v, "type", "patch")
        if r is None:
            s = set_ovsdb_attr(ovsdb, "Interface", v, "options", p, "peer")
            if s is not None:
                raise ValueError(str(s))
        else:
            raise ValueError(str(r))

    def config_portnum_instance():
        ret = set_ovsdb_attr(ovsdb, "Interface", port, "ofport_request", portnum)
        if ret is not None:
            raise ValueError(str(ret))

    def get_portnum():
        p1 = get_ovsdb_attr(ovsdb, "Interface", port, "ofport")[0]
        p2 = get_ovsdb_attr(ovsdb, "Interface", peer, "ofport")[0]
        return p1, p2

    try:
        create(instance, port)
        create(transport, peer)
        config_vport(port, peer)
        config_vport(peer, port)
        if portnum is not None:
            config_portnum_instance()
        return False, get_portnum()
    except Exception as ex:
        return True, str(ex)


def del_vport(ovsdb, instance, portnum):
    port, peer = get_port(ovsdb, instance, portnum)
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def remove_port(b, p):
        r = run_command(ovsdb, 'del-port', [b, p])
        if r is not None:
            raise ValueError(str(r))

    try:
        if port is not None:
            remove_port(instance, port)
            if peer is not None:
                remove_port(transport, peer)

            return False, None
        else:
            raise ValueError("the port <{p}> is not attached to instance <{i}>".format(p=port, i=instance))
    except Exception as ex:
        pass
    """
    def remove():
        if bridge_exist(ovsdb, instance):
    """


PROTO = ofproto_v1_3
PARSER = ofproto_v1_3_parser

config = {
    'prefix': None,
    'url': os.environ['ORCH_ADDR'],
    "realm": os.environ['ORCH_REALM']
}

cmd_supported = {
    "add": PROTO.OFPFC_ADD,
    "modify": PROTO.OFPFC_MODIFY,
    "modify_strict": PROTO.OFPFC_MODIFY_STRICT,
    "delete": PROTO.OFPFC_DELETE,
    "delete_strict": PROTO.OFPFC_DELETE_STRICT
}


def send_mod(dp, out_port, match, inst, cmd):
    cookie = cookie_mask = 0
    table_id = 0
    idle_timeout = hard_timeout = 0
    priority = 0
    buffer_id = PROTO.OFP_NO_BUFFER
    out_group = PROTO.OFPG_ANY
    flags = 0

    req = PARSER.OFPFlowMod(datapath=dp,
                            cookie=cookie,
                            cookie_mask=cookie_mask,
                            table_id=table_id,
                            command=cmd,
                            idle_timeout=idle_timeout,
                            hard_timeout=hard_timeout,
                            priority=priority,
                            buffer_id=buffer_id,
                            out_port=out_port,
                            out_group=out_group,
                            flags=flags,
                            match=match,
                            instructions=inst)

    return dp.send_msg(req)


class VSDNAgentService(ApplicationSession):
    def __int__(self, *args, **kwargs):
        super(VSDNAgentService, self).__int__(*args, **kwargs)
        self._ovsdb = kwargs.get("ovsdb")
        self._opflw = kwargs.get("opflw")

    @wamp.register(uri="{p}.add_instance".format(p=config.get('prefix')))
    def add_instance(self, label, datapath_id, protocols):
        try:
            set_bridge(self._ovsdb, label, datapath_id, protocols)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.rem_instance".format(p=config.get('prefix')))
    def rem_instance(self, label):
        try:
            del_bridge(self._ovsdb, label)
            return False, None
        except Exception as ex:
            return True, str(ex)


class VSDNAgentController(RyuApp):
    def __init__(self, *_args, **_kwargs):
        super(VSDNAgentController, self).__init__(*_args, **_kwargs)
