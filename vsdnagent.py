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
    print(ret)
    if ret is not None:
        raise ValueError(str(ret))


def get_dpid(ovsdb, bridge):
    return get_ovsdb_attr(ovsdb, "Bridge", bridge, "datapath_id")[0][0]


def set_dpid(ovsdb, bridge, dpid):
    ret = set_ovsdb_attr(ovsdb, "Bridge", bridge, "other_config", dpid, "datapath-id")
    if ret is not None:
        raise ValueError(str(ret))


def get_port(ovsdb, bridge, portnum):
    assert check_ovs_service(), "the ovsdb service is not available"
    ports = run_command(ovsdb, 'list-ports', [bridge])
    if len(ports) == 0:
        raise ValueError("there is no ports on virtual bridge <{b}> ".format(b=bridge))
    for port in ports:
        pn = get_ovsdb_attr(ovsdb, 'Interface', port, "ofport")[0][0]
        if pn == int(portnum):
            type = get_ovsdb_attr(ovsdb, 'Interface', port, "type")[0]
            if type == 'patch':
                peer = get_ovsdb_attr(ovsdb, 'Interface', port, "options")[0]['peer']
                return port, peer
            return port, None
    return None, None


def get_peer_portnum(ovsdb, bridge, portnum):
    assert check_ovs_service(), "the ovsdb service is not available"
    ports = run_command(ovsdb, 'list-ports', [bridge])
    if len(ports) == 0:
        raise ValueError("there is no ports on virtual bridge <{b}> ".format(b=bridge))
    for port in ports:
        pn = get_ovsdb_attr(ovsdb, 'Interface', port, "ofport")[0][0]
        if pn == int(portnum):
            peer = get_ovsdb_attr(ovsdb, 'Interface', port, "options")[0]['peer']
            pn_peer = get_ovsdb_attr(ovsdb, 'Interface', peer, "ofport")[0][0]
            return pn_peer

    return None


def set_controller(ovsdb, bridge, controller):
    assert check_ovs_service(), "the ovsdb service is not available"
    assert isinstance(controller, list), "the controller value must be a list"
    assert len(controller), "One controller must be "

    ctl = ",".join(controller)
    ret = run_command(ovsdb, 'set-controller', [bridge, controller])
    if ret is not None:
        raise ValueError(str(ret))

def del_controller(ovsdb, bridge):
    assert check_ovs_service(), "the ovsdb service is not available"
    ret = run_command(ovsdb, 'del-controller', [bridge])
    if ret is not None:
        raise ValueError(str(ret))


def set_bridge(ovsdb, label, datapath_id=None, protocols=None):
    def create():
        if not bridge_exist(ovsdb, label):
            ret = run_command(ovsdb, "add-br", [label])
            if ret is not None:
                raise ValueError(str(ret))
        else:
            raise ValueError("A virtual instance <{i}> with name already exists on device".format(i=label))

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
    if check_ovs_service():
        if bridge_exist(ovsdb, label):
            ret = run_command(ovsdb, 'del-br', [label])
            if ret is not None:
                raise ValueError(str(ret))
        else:
            raise ValueError("the virtual instance <{i}> is not exist".format(i=label))
    else:
        raise ValueError("the ovsdb service is not available")


# TODO Change the try catch to check_ovs_service
def add_vport(ovsdb, label, portnum=None, realport=None, vlan_id=None):
    port = "V{i}".format(i=str(uuid.uuid4())[:8])
    peer = "R{i}".format(i=str(uuid.uuid4())[:8])
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def create(b, p):
        if bridge_exist(ovsdb, b):
            ret = run_command(ovsdb, 'add-port', [b, p])
            if ret is not None:
                raise ValueError(str(ret))

    def config_vport(v, p, r=None, vl=None):
        ph = set_ovsdb_attr(ovsdb, "Interface", v, "type", "patch")
        if ph is None:
            pr = set_ovsdb_attr(ovsdb, "Interface", v, "options", p, "peer")
            if pr is not None:
                raise ValueError(str(pr))
        else:
            raise ValueError(str(r))

        if r is not None:
            t = set_ovsdb_attr(ovsdb, "Interface", v, "external_ids", int(r), "realport")
            if t is not None:
                raise ValueError(str(pr))

        if vl is not None:
            u = set_ovsdb_attr(ovsdb, "Interface", v, "external_ids", int(vl), "vlan_id")
            if u is not None:
                raise ValueError(str(pr))

    def config_portnum_instance(p):
        ret = set_ovsdb_attr(ovsdb, "Interface", p, "ofport_request", portnum)
        if ret is not None:
            raise ValueError(str(ret))

    def get_portnum():
        p1 = get_ovsdb_attr(ovsdb, "Interface", port, "ofport")[0][0]
        p2 = get_ovsdb_attr(ovsdb, "Interface", peer, "ofport")[0][0]
        return p1, p2

    if check_ovs_service():
        create(label, port)
        create(transport, peer)
        config_vport(port, peer)
        config_vport(peer, port, realport, vlan_id)
        if portnum is not None:
            config_portnum_instance(port)

        return get_portnum()
    else:
        raise ValueError("the ovsdb service is not available")


def del_vport(ovsdb, label, portnum):
    port, peer = get_port(ovsdb, label, portnum)
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def remove_port(b, p):
        r = run_command(ovsdb, 'del-port', [b, p])
        if r is not None:
            raise ValueError(str(r))

    if check_ovs_service():
        if port is not None:
            remove_port(label, port)
            if peer is not None:
                remove_port(transport, peer)
        else:
            raise ValueError("the port <{p}> is not attached to instance <{i}>".format(p=port, i=label))
    else:
        raise ValueError("the ovsdb service is not available")


PROTO = ofproto_v1_3
PARSER = ofproto_v1_3_parser

config = {
    'prefix': os.environ['AGENT_PREFIX'],
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


def rule_link_port(dp, in_port, out_port, vlan_id, cmd, by_pass=False):
    mod_cmd = cmd_supported.get(cmd, None)
    if mod_cmd is None:
        raise ValueError("command not found")

    def rule_ingress():
        a = []
        i = []

        if by_pass:
            a.append(PARSER.OFPActionOutput(port=int(out_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port=int(in_port), vlan_id=(0x1000 | int(vlan_id)))
        else:

            a.append(PARSER.OFPActionPopVlan())
            a.append(PARSER.OFPActionOutput(port=int(out_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port=int(in_port), vlan_vid=(int(vlan_id) + 0x1000))

        return i, m

    def rule_egress():
        ethertype = 33024
        a = []
        i = []

        if by_pass:
            a.append(PARSER.OFPActionOutput(port=int(in_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port=int(out_port), vlan_id=(0x1000 | int(vlan_id)))

            return i, m

        else:
            a.append(PARSER.OFPActionPushVlan(ethertype))
            a.append(PARSER.OFPActionSetField(vlan_vid=(int(vlan_id) + 0x1000)))
            a.append(PARSER.OFPActionOutput(port=int(in_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port=int(out_port))

            return i, m

    if dp.is_active():
        ii, mi = rule_ingress()
        ing = send_mod(dp, int(out_port), mi, ii, mod_cmd)
        if not ing:
            raise ValueError("it is not possible to apply the rules to device")

        ie, me = rule_egress()
        egr = send_mod(dp, int(in_port), me, ie, mod_cmd)
        if not egr:
            raise ValueError("it is not possible to apply the rules to device")
    else:
        raise ValueError("the switch is not available")


class VSDNAgentService(ApplicationSession):
    def __int__(self, *args, **kwargs):
        super(VSDNAgentService, self).__int__(*args, **kwargs)
        self._ovsdb = kwargs.get("ovsdb")
        self._opflw = kwargs.get("opflw")

    @wamp.register(uri="{p}.add_instance".format(p=os.environ['AGENT_PREFIX']))
    def _add_instance(self, label, datapath_id, protocols):
        try:
            set_bridge(self._ovsdb, label, datapath_id, protocols)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.rem_instance".format(p=os.environ['AGENT_PREFIX']))
    def _rem_instance(self, label):
        try:
            del_bridge(self._ovsdb, label)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.add_vport".format(p=os.environ['AGENT_PREFIX']))
    def _add_vport(self, label, portnum, realport, vlan_id):
        try:
            _, port2 = add_vport(self._ovsdb, label, portnum, realport)
            rule_link_port(self._opflw, realport, port2, vlan_id, 'add')
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.rem_vport".format(p=os.environ['AGENT_PREFIX']))
    def _rem_vport(self, label, portnum):
        try:
            _, peer = get_port(self._ovsdb, label, portnum)
            in_port = get_peer_portnum(self._ovsdb, label, portnum)
            out_port = get_ovsdb_attr(self._ovsdb, "Interface", peer, "external_id")[0]['realport']
            vlan_id = get_ovsdb_attr(self._ovsdb, "Interface", peer, "external_id")[0]['vlan_id']
            rule_link_port(self._opflw, in_port, out_port, vlan_id, "delete")
            del_vport(self._ovsdb, label, portnum)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.add_by_pass".format(p=os.environ['AGENT_PREFIX']))
    def _add_by_pass(self, in_realport, out_realport, vlan_id):
        try:
            rule_link_port(self._opflw, in_realport, out_realport, vlan_id, "add", True)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.rem_by_pass".format(p=os.environ['AGENT_PREFIX']))
    def _rem_by_pass(self, in_realport, out_realport, vlan_id):
        try:
            rule_link_port(self._opflw,in_realport, out_realport, vlan_id, "delete", True)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.set_controller".format(p=os.environ['AGENT_PREFIX']))
    def _set_controller(self, label, controller):
        try:
            set_controller(self._ovsdb, label, controller)
            return False, None
        except Exception as ex:
            return True, str(ex)

    @wamp.register(uri="{p}.del_controller".format(p=os.environ['AGENT_PREFIX']))
    def _del_controller(self, label):
        try:
            del_controller(self._ovsdb, label)
            return False, None
        except Exception as ex:
            return True, str(ex)


class VSDNAgentController(RyuApp):
    def __init__(self, *_args, **_kwargs):
        super(VSDNAgentController, self).__init__(*_args, **_kwargs)








