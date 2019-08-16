import logging
import uuid

from ryu.lib.ovs.vsctl import VSCtlCommand, VSCtl

logger = logging.getLogger(__name__)


def check_ovs_service(ip, port):
    def check_version(ovs):
        cmd = VSCtlCommand('list', ['Open_vSwitch'])
        ovs.run_command(commands=[cmd], exception=ValueError)
        version = dict(cmd.result[0].__dict__)["_data"]["ovs_version"]
        logger.debug("openvswitch version {}".format(version))
    try:
        ovs = VSCtl("tcp:{}:{}".format(ip, port))
        check_version(ovs)
        return True
    except Exception as ex:
        return False


class OVSController(object):
    def __init__(self, addr, port):
        self.db = VSCtl('tcp:{ip}:{port}'.format(ip=addr, port=port))
        self.addr = addr
        self.port = port

    def run_command(self, cmd, args):
        assert check_ovs_service(self.addr, int(self.port)), "the ovsdb service is not available"
        command = VSCtlCommand(cmd, args)
        self.db.run_command([command])
        return command.result

    def get_ovsdb_attr(self, table, record, column, key=None):
        if key is not None:
            column = "{c}:{k}".format(c=column, k=key)
        return self.run_command("get", [table, record, column])

    def set_ovsdb_attr(self, table, record, column, value, key=None):
        if key is not None:
            column = "{c}:{k}".format(c=column, k=key)
        ret = self.run_command("set", [table, record, "{c}={v}".format(c=column, v=value)])
        if ret is not None:
            raise ValueError(str(ret))

    def bridge_exist(self, bridge):
        return self.run_command("br-exists", [bridge])

    def get_dpid(self, bridge):
        return self.get_ovsdb_attr("Bridge", bridge, "datapath_id")[0][0]

    def set_dpid(self, bridge, dpid):
        ret = self.set_ovsdb_attr("Bridge", bridge, "other_config", dpid, "datapath-id")
        if ret is not None:
            raise ValueError(str(ret))

    def get_port(self, bridge, portnum):
        ports = self.run_command('list-ports', [bridge])
        if len(ports) == 0:
            raise ValueError("there is no ports on virtual bridge <{b}> ".format(b=bridge))
        for port in ports:
            pn = self.get_ovsdb_attr('Interface', port, "ofport")[0][0]
            if pn == int(portnum):
                return port
        return None

    def get_peer_port(self, bridge, portnum):
        port = self.get_port(bridge, portnum)
        if port is None:
            return None
        else:
            type = self.get_ovsdb_attr('Interface', port, "type")[0]
            if type != 'patch':
                return None
            else:
                peer_port = self.get_ovsdb_attr('Interface', port, "options")[0]['peer']
        return peer_port

    def get_peer_portnum(self, bridge, portnum):
        peer = self.get_peer_port(bridge, portnum)
        if peer is None:
            raise ValueError('there no peer port')
        peer_portnum = self.get_ovsdb_attr('Interface', peer, "ofport")[0][0]
        return peer_portnum

    def set_controller(self, bridge, controller):
        assert isinstance(controller, list), "the controller value must be a list"
        assert len(controller), "One controller must be "

        ctl = ",".join(controller)
        ret = self.run_command('set-controller', [bridge, ctl])
        if ret is not None:
            raise ValueError(str(ret))

    def del_controller(self, bridge):
        ret = self.run_command('del-controller', [bridge])
        if ret is not None:
            raise ValueError(str(ret))

    def set_bridge(self, name, datapath_id=None, protocols=None):
        def create():
            if not self.bridge_exist(name):
                ret = self.run_command("add-br", [name])
                if ret is not None:
                    raise ValueError(str(ret))
            else:
                raise ValueError("A virtual switch <{i}> with name already exists on device".format(i=name))

        def config():
            if datapath_id is not None:
                ret = self.set_ovsdb_attr("Bridge", name, "other_config", datapath_id, "datapath-id")
                if ret is not None:
                    raise ValueError(str(ret))

            if protocols is not None:
                assert (isinstance(protocols, list)), 'the protocols must be a list object'
                proto = ",".join(protocols)
                ret = self.set_ovsdb_attr('Bridge', name, 'protocols', proto)
                if ret is not None:
                    raise ValueError(str(ret))

        try:
            create()
            config()
            return self.get_dpid(name)
        except Exception as ex:
            raise ValueError(str(ex))

    def del_bridge(self, name):
        if self.bridge_exist(name):
            ret = self.run_command('del-br', [name])
            if ret is not None:
                raise ValueError(str(ret))
        else:
            raise ValueError("the virtual switch <{i}> is not exist".format(i=name))

    def add_patch_port(self, bridge_source, bridge_target, portnum_source=None, portnum_target=None):

        def get_ports():
            port = "V{i}".format(i=str(uuid.uuid4())[:8])
            peer = "R{i}".format(i=str(uuid.uuid4())[:8])
            return port, peer

        def set_port(b, p):
            if self.bridge_exist(b):
                ret = self.run_command('add-port', [b, p])
                if ret is not None:
                    raise ValueError(str(ret))

        def config_link_port(src, tgt, portnum=None):
            err1 = self.set_ovsdb_attr("Interface", src, "type", "patch")
            if err1 is not None:
                raise ValueError(str(err1))

            err2 = self.set_ovsdb_attr("Interface", src, "options", tgt, "peer")
            if err2 is not None:
                raise ValueError(str(err2))

            if portnum is not None:
                err3 = self.set_ovsdb_attr("Interface", src, "ofport_request", portnum)
                if err3 is not None:
                    raise ValueError(str(err3))

        def get_portnum(port, peer):
            p1 = self.get_ovsdb_attr("Interface", port, "ofport")[0][0]
            p2 = self.get_ovsdb_attr("Interface", peer, "ofport")[0][0]
            return p1, p2

        try:
            port, peer = get_ports()
            set_port(bridge_source, port)
            config_link_port(port, peer, portnum_source)
            set_port(bridge_target, peer)
            config_link_port(peer, port, portnum_target)

            return get_portnum(port, peer)
        except Exception as ex:
            raise ValueError(str(ex))

    def rem_patch_port(self, bridge, portnum):

        def get_ports():
            port = self.get_port(bridge, portnum)
            peer = self.get_peer_port(bridge, portnum)
            return port, peer

        def get_bridge(p):
            br = self.run_command('iface-to-br', [p])
            return br

        def remove_port(b, p):
            r = self.run_command('del-port', [b, p])
            if r is not None:
                raise ValueError(str(r))

        try:
            port, peer = get_ports()
            bridge_peer = get_bridge(peer)
            remove_port(bridge, port)
            remove_port(bridge_peer, peer)
        except Exception as ex:
            raise ValueError(str(ex))


if __name__ == '__main__':
    print(check_ovs_service('172.17.0.2', '6640'))
    #

    # print(ovs.bridge_exist("tswitch0"))

    # ovs.run_command("remove", ['Interface', 'tswitch0', 'external_ids', '1=portnum_phy'])
