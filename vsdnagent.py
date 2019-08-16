import socket
import os
import uuid
import threading
import signal
import socket

from ryu.base.app_manager import RyuApp
from ryu.lib.ovs.vsctl import VSCtlCommand, VSCtl
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner, inlineCallbacks
from autobahn import wamp
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.topology import event as oflw_evt
from ryu.controller.handler import set_ev_cls
from ryu.topology.switches import dpid_to_str



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

    req = PARSER.OFPFlowMod(datapath = dp,
                            cookie = cookie,
                            cookie_mask = cookie_mask,
                            table_id = table_id,
                            command = cmd,
                            idle_timeout = idle_timeout,
                            hard_timeout = hard_timeout,
                            priority = priority,
                            buffer_id = buffer_id,
                            out_port = out_port,
                            out_group = out_group,
                            flags = flags,
                            match = match,
                            instructions = inst)

    return dp.send_msg(req)


def rule_link_port(dp, in_port, out_port, vlan_id, cmd, by_pass = False):
    mod_cmd = cmd_supported.get(cmd, None)
    if mod_cmd is None:
        raise ValueError("command not found")

    def rule_ingress():
        a = []
        i = []

        if by_pass:
            a.append(PARSER.OFPActionOutput(port = int(out_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port = int(in_port), vlan_id = (0x1000 | int(vlan_id)))
        else:

            a.append(PARSER.OFPActionPopVlan())
            a.append(PARSER.OFPActionOutput(port = int(out_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port = int(in_port), vlan_vid = (int(vlan_id) + 0x1000))

        return i, m

    def rule_egress():
        ethertype = 33024
        a = []
        i = []

        if by_pass:
            a.append(PARSER.OFPActionOutput(port = int(in_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port = int(out_port), vlan_id = (0x1000 | int(vlan_id)))

            return i, m

        else:
            a.append(PARSER.OFPActionPushVlan(ethertype))
            a.append(PARSER.OFPActionSetField(vlan_vid = (int(vlan_id) + 0x1000)))
            a.append(PARSER.OFPActionOutput(port = int(in_port)))
            i.append(PARSER.OFPInstructionActions(PROTO.OFPIT_APPLY_ACTIONS, a))
            m = PARSER.OFPMatch(in_port = int(out_port))

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

    def set_ovsdb(self, db):
        self._ovsdb = db

    def set_opflw(self, dp):
        self._opflw = dp

    @inlineCallbacks
    def register_device(self):
        yield self.publish("topologyservice.new_device",
                           datapath_id = dpid_to_str(self._opflw.id),
                           prefix_uri = os.environ['AGENT_PREFIX'],
                           label = "of:device:{i}".format(i = dpid_to_str(self._opflw.id)))

    @inlineCallbacks
    def register_procedures(self):

        def _add_vswitch(label, datapath_id, protocols):
            try:
                set_bridge(self._ovsdb, label, datapath_id, protocols)
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _rem_vswitch(label):
            try:
                del_bridge(self._ovsdb, label)
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _add_vport(label, portnum, realport, vlan_id):
            try:
                _, port2 = add_vport(self._ovsdb, label, portnum, realport)
                rule_link_port(self._opflw, realport, port2, vlan_id, 'add')
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _rem_vport(label, portnum):
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

        def _add_by_pass(in_realport, out_realport, vlan_id):
            try:
                rule_link_port(self._opflw, in_realport, out_realport, vlan_id, "add", True)
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _rem_by_pass(in_realport, out_realport, vlan_id):
            try:
                rule_link_port(self._opflw, in_realport, out_realport, vlan_id, "delete", True)
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _set_controller(label, controller):
            try:
                set_controller(self._ovsdb, label, controller)
                return False, None
            except Exception as ex:
                return True, str(ex)

        def _del_controller(label):
            try:
                del_controller(self._ovsdb, label)
                return False, None
            except Exception as ex:
                return True, str(ex)

        yield self.register(_add_vswitch, '{p}.add_vswitch'.format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_rem_vswitch, '{p}.rem_vswitch'.format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_add_vport, "{p}.add_vport".format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_rem_vport, "{p}.rem_vport".format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_add_by_pass, "{p}.add_by_pass".format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_rem_by_pass, "{p}.rem_by_pass".format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_set_controller, "{p}.set_controller".format(p = os.environ['AGENT_PREFIX']))
        yield self.register(_del_controller, "{p}.del_controller".format(p = os.environ['AGENT_PREFIX']))

        self.log.info("8 procedures has registred")

    def onJoin(self, details):
        self.log.info("vSDNOrches orchestrator was reached")
        self.log.info("Prefix agent: {p}".format(p = os.environ['AGENT_PREFIX']))
        self.register_procedures()
        self.register_device()

        @inlineCallbacks
        def unregister_device(sig, frame):
            msg = {"datapath_id": dpid_to_str(self._opflw.id),
                   "prefix_uri": os.environ['AGENT_PREFIX'],
                   "label": "of:device:{i}".format(i = dpid_to_str(self._opflw.id))}

            yield self.publish("topologyservice.rem_device", msg)
            yield self.leave()

        signal.signal(signal.SIGINT, unregister_device)

    def onLeave(self, details):
        self.disconnect()


class VSDNAgentController(RyuApp):
    def __init__(self, *_args, **_kwargs):
        super(VSDNAgentController, self).__init__(*_args, **_kwargs)
        self._ovsdb = None
        self._datapath = None

    def _set_prefix(self, dpid):
        os.environ['AGENT_PREFIX'] = "agent.{id}".format(id = dpid)

    def _get_prefix(self):
        return os.environ['AGENT_PREFIX']

    def _set_datapath(self, dp):
        self._datapath = dp

    def _get_datapath(self):
        return self._datapath

    def _set_ovsdb(self, db_addr):
        self._ovsdb = VSCtl(db_addr)

    def _get_ovsdb(self):
        return self._ovsdb

    def _start_wamp(self):
        try:
            app = VSDNAgentService()
            app.set_opflw(self._datapath)
            app.set_ovsdb(self._ovsdb)
            runner = ApplicationRunner(url = os.environ["ORCH_ADDR"], realm = os.environ["ORCH_REALM"])
            runner.run(app, auto_reconnect = True)
        except Exception as ex:
            self.logger.error(str(ex))
            self.logger.error("vSDNOrches Orchestrator not found, retry...")

    @set_ev_cls(oflw_evt.EventSwitchEnter)
    def _switch_enter(self, ev):
        self._set_datapath(ev.switch.dp)
        self._set_prefix(dpid_to_str(self._get_datapath().id))
        db_address, _ = self._get_datapath().address

        self.logger.info("new switch <{i}> has attached to agent <{a}>".format(i = dpid_to_str(self._get_datapath().id),
                                                                               a = self._get_prefix()))

        if check_ovs_service():
            self.logger.info("the ovsdb service has reached by agent")
            self._set_ovsdb(db_addr = "tcp:{a}:6640".format(a = db_address))
        else:
            self.logger.error(
                "ovsdb service not was reached in tcp:{a}:6640 , enable it 'set-manager ptcp:6640'".format(
                    a = db_address))

        t = threading.Thread(target = self._start_wamp)
        t.start()


if __name__ == '__main__':
    db = VSCtl('tcp:192.168.0.5:6640')
    ret = bridge_exist(db, 'vswitch1')
    print(ret)
