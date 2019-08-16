import os
import socket
import uuid

from ryu.lib.ovs.vsctl import VSCtlCommand, VSCtl


class OVSController(object):
    def __init__(self, addr, port):
        self.db = VSCtl('tcp:{ip}:{port}'.format(ip=addr, port=port))
        self.addr = addr
        self.port = port

    def check_ovs_service(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        if result == 0:
            sock.close()
            return True
        else:
            sock.close()
            return False

    def _run_command(self, cmd, args):
        assert self.check_ovs_service(self.addr, int(self.port)), "the ovsdb service is not available"
        command = VSCtlCommand(cmd, args)
        self.db.run_command([command])
        return command.result

    def get_ovsdb_attr(self, table, record, column, key = None):
        if key is not None:
            column = "{c}:{k}".format(c = column, k = key)
        return self._run_command("get", [table, record, column])

    def set_ovsdb_attr(self, table, record, column, value, key = None):
        if key is not None:
            column = "{c}:{k}".format(c = column, k = key)
        ret = self._run_command("set", [table, record, "{c}={v}".format(c = column, v = value)])
        if ret is not None:
            raise ValueError(str(ret))

    def bridge_exist(self, bridge):
        return self._run_command("br-exists", [bridge])

    def get_dpid(self, bridge):
        return self.get_ovsdb_attr("Bridge", bridge, "datapath_id")[0][0]


def set_dpid(db, bridge, dpid):
    ret = set_ovsdb_attr(db, "Bridge", bridge, "other_config", dpid, "datapath-id")
    if ret is not None:
        raise ValueError(str(ret))


def get_port(db, bridge, portnum):
    ports = run_command(db, 'list-ports', [bridge])
    if len(ports) == 0:
        raise ValueError("there is no ports on virtual bridge <{b}> ".format(b = bridge))
    for port in ports:
        pn = get_ovsdb_attr(db, 'Interface', port, "ofport")[0][0]
        if pn == int(portnum):
            return port
    return None


def get_peer_port(db, bridge, portnum):
    port = get_port(db, bridge, portnum)
    if port is None:
        return None
    else:
        type = get_ovsdb_attr(db, 'Interface', port, "type")[0]
        if type != 'patch':
            return None
        else:
            peer_port = get_ovsdb_attr(db, 'Interface', port, "options")[0]['peer']
    return peer_port


def get_peer_portnum(db, bridge, portnum):
    peer = get_peer_port(db, bridge, portnum)
    if peer is None:
        raise ValueError('there no peer port')
    peer_portnum = get_ovsdb_attr(db, 'Interface', peer, "ofport")[0][0]
    return peer_portnum




def set_controller(db, bridge, controller):
    assert isinstance(controller, list), "the controller value must be a list"
    assert len(controller), "One controller must be "

    ctl = ",".join(controller)
    ret = run_command(db, 'set-controller', [bridge, ctl])
    if ret is not None:
        raise ValueError(str(ret))


def del_controller(db, bridge):
    ret = run_command(db, 'del-controller', [bridge])
    if ret is not None:
        raise ValueError(str(ret))


def set_bridge(db, label, datapath_id = None, protocols = None):
    def create():
        if not bridge_exist(db, label):
            ret = run_command(db, "add-br", [label])
            if ret is not None:
                raise ValueError(str(ret))
        else:
            raise ValueError("A virtual switch <{i}> with name already exists on device".format(i = label))

    def config():
        if datapath_id is not None:
            ret = set_ovsdb_attr(db, "Bridge", label, "other_config", datapath_id, "datapath-id")
            if ret is not None:
                raise ValueError(str(ret))

        if protocols is not None:
            assert (isinstance(protocols, list)), 'the protocols must be a list object'
            proto = ",".join(protocols)
            ret = set_ovsdb_attr(db, 'Bridge', label, 'protocols', proto)
            if ret is not None:
                raise ValueError(str(ret))

    try:
        create()
        config()
        return get_dpid(db, label)
    except Exception as ex:
        raise ValueError(str(ex))

def del_bridge(db, label):
    if bridge_exist(db, label):
        ret = run_command(db, 'del-br', [label])
        if ret is not None:
            raise ValueError(str(ret))
    else:
        raise ValueError("the virtual switch <{i}> is not exist".format(i = label))


def add_vport(db, bridge, portnum = None):
    port = "V{i}".format(i = str(uuid.uuid4())[:8])
    peer = "R{i}".format(i = str(uuid.uuid4())[:8])
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def create(b, p):
        if bridge_exist(db, b):
            ret = run_command(db, 'add-port', [b, p])
            if ret is not None:
                raise ValueError(str(ret))

    def config_vport(vp, pp):
        ret = set_ovsdb_attr(db, "Interface", vp, "type", "patch")
        if ret is not None:
            raise ValueError(str(ret))

        ret = set_ovsdb_attr(db, "Interface", vp, "options", pp, "peer")
        if ret is not None:
            raise ValueError(str(ret))

    def config_portnum(p):
        ret = set_ovsdb_attr(db, "Interface", p, "ofport_request", portnum)
        if ret is not None:
            raise ValueError(str(ret))

    def get_portnum():
        p1 = get_ovsdb_attr(db, "Interface", port, "ofport")[0][0]
        p2 = get_ovsdb_attr(db, "Interface", peer, "ofport")[0][0]
        return p1, p2

    if check_ovs_service(db):
        create(bridge, port)
        create(transport, peer)
        config_vport(port, peer)
        config_vport(peer, port)
        if portnum is not None:
            config_portnum(port)

        return get_portnum()
    else:
        raise ValueError("the ovsdb service is not available")


def del_vport(db, bridge, portnum):
    port = get_port(db, bridge, portnum)
    peer = get_peer_port(db, bridge, portnum)
    transport = os.environ['ORCH_TRANS_BRIDGE']

    def remove_port(b, p):
        r = run_command(db, 'del-port', [b, p])
        if r is not None:
            raise ValueError(str(r))

    remove_port(bridge, port)
    remove_port(transport, peer)
