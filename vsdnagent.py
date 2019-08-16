import multiprocessing as mp
import os
import signal

import coloredlogs
from autobahn.twisted.wamp import ApplicationSession, ApplicationRunner, inlineCallbacks
from autobahn.wamp.exception import ApplicationError
from ryu.base.app_manager import RyuApp
from ryu.controller.handler import set_ev_cls
from ryu.topology import event as oflw_evt
from ryu.topology.switches import dpid_to_str

from openflow import OFLWController
from ovsdb import OVSController, check_ovs_service


def get_procedure(name, prefix=None):
    if prefix is None:
        prefix = os.environ['AGENT_PREFIX']
    return "{p}.{n}".format(p=prefix, n=name)


class VSDNAgentService(ApplicationSession):

    def __init__(self, ovs: OVSController, oflw: OFLWController, config=None):
        super().__init__(config=None)
        self._oflw = oflw
        self._ovs = ovs

    def _add_vswitch(self, name, datapath_id, protocols):
        try:
            self._ovs.set_bridge(name, datapath_id, protocols)
            dpid = self._ovs.get_dpid(name)
            self.log.info("new virtual switch {} has created with dpid {}".format(name, dpid))
        except Exception as ex:
            error = '{p}.error.add_switch'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _rem_vswitch(self, name):
        try:
            self._ovs.del_bridge(name)
            self.log.info("<i> virtual switch has removed".format(i=name))
        except Exception as ex:
            error = '{p}.error.rem_switch'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _add_vport(self, vswitch, vlan_id, source_portnum, phy_portnum):

        def register_phy():
            port = self._ovs.get_port(vswitch, source_portnum)
            self._ovs.set_ovsdb_attr('Interface', port, 'external_ids', phy_portnum, 'phy_portnum')
            self.log.info("register phy interface {}".format(phy_portnum))

        def add_vport():
            bridge_source = vswitch
            bridge_target = os.environ['ORCH_TRANS_BRIDGE']
            self._ovs.add_patch_port(bridge_source, bridge_target, source_portnum)
            self.log.info("added vport {} on patch {}:{}".format(phy_portnum, bridge_source, bridge_target))

        def add_rules():
            portnum_peer = self._ovs.get_peer_portnum(vswitch, source_portnum)
            self._oflw.rule_link_port(portnum_peer, phy_portnum, vlan_id, 'add', by_pass=False)
            self.log.info('set rules openflow')

        try:
            add_vport()
            #add_rules()
            register_phy()
        except Exception as ex:
            error = '{p}.error.add_vport'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _rem_vport(self, vswitch, vlan_id, portnum):

        def get_phy_portnum():
            port = self._ovs.get_port(vswitch, portnum)
            pp = self._ovs.get_ovsdb_attr('Interface', port, 'external_ids', 'phy_portnum')
            return pp

        try:
            self._ovs.rem_patch_port(vswitch, portnum)
            peer_portnum = self._ovs.get_peer_portnum(vswitch, portnum)
            phy_portnum = get_phy_portnum()
            self._oflw.rule_link_port(peer_portnum, phy_portnum, vlan_id, 'delete')

        except Exception as ex:
            error = '{p}.error.rem_vport'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _add_by_pass(self, phyport_in, phyport_out, vlan_id):
        try:
            self._oflw.rule_link_port(phyport_in, phyport_out, vlan_id, 'add', by_pass=True)
        except Exception as ex:
            error = '{p}.error.add_bypass'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _rem_by_pass(self, phyport_in, phyport_out, vlan_id):
        try:
            self._oflw.rule_link_port(phyport_in, phyport_out, vlan_id, 'delete', by_pass=True)
        except Exception as ex:
            error = '{p}.error.rem_bypass'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _set_controller(self, vswitch, controller):
        try:
            self._ovs.set_controller(vswitch, controller)
        except Exception as ex:
            error = '{p}.error.set_controller'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def _del_controller(self, vswitch):
        try:
            self._ovs.del_controller(vswitch)
        except Exception as ex:
            error = '{p}.error.rem_controller'.format(p=os.environ['AGENT_PREFIX'])
            raise ApplicationError(error, msg=str(ex))

    def onUserError(self, fail, msg):
        print("{} : {}".format(fail, msg))

    @inlineCallbacks
    def onJoin(self, details):
        self.log.info("Starting vSDNAgentService")
        self.log.info("Prefix agent: {p}".format(p=os.environ['AGENT_PREFIX']))

        yield self.register(self._add_vswitch, get_procedure('add_vswitch'))
        yield self.register(self._rem_vswitch, get_procedure('rem_vswitch'))
        yield self.register(self._add_vport, get_procedure('add_vport'))
        yield self.register(self._rem_vport, get_procedure('rem_vport'))
        yield self.register(self._add_by_pass, get_procedure('add_bypass'))
        yield self.register(self._rem_by_pass, get_procedure('rem_bypass'))
        yield self.register(self._set_controller, get_procedure('add_controller'))
        yield self.register(self._del_controller, get_procedure('rem_controller'))

        yield self.publish("topologyservice.new_device",
                           datapath_id=self._oflw.get_dpid(),
                           prefix_uri=os.environ['AGENT_PREFIX'],
                           label=self._oflw.get_dpid())

        self.log.info("Started vSDNAgentService")

        @inlineCallbacks
        def unregister_device(sig, frame):
            msg = {"datapath_id": dpid_to_str(self._opflw.id),
                   "prefix_uri": os.environ['AGENT_PREFIX'],
                   "label": "of:device:{i}".format(i=dpid_to_str(self._opflw.id))}

            yield self.publish("topologyservice.rem_device", msg)
            yield self.leave()

        signal.signal(signal.SIGINT, unregister_device)

    def onLeave(self, details):
        self.disconnect()


class VSDNAgentController(RyuApp):
    def __init__(self, *_args, **_kwargs):
        super(VSDNAgentController, self).__init__(*_args, **_kwargs)
        coloredlogs.install(logger=self.logger)
        self._ovsdb = None
        self._datapath = None

    def set_prefix(self, dpid):
        os.environ['AGENT_PREFIX'] = "agent.{id}".format(id=dpid)

    def get_prefix(self):
        return os.environ['AGENT_PREFIX']

    def set_datapath(self, dp):
        self._datapath = OFLWController(dp)

    def get_datapath(self):
        return self._datapath

    def set_ovsdb(self, addr, port):
        self._ovsdb = OVSController(addr, port)

    def get_ovsdb(self):
        return self._ovsdb

    def _start_wamp(self):
        try:
            app = VSDNAgentService(ovs=self.get_ovsdb(), oflw=self.get_datapath())
            runner = ApplicationRunner(url=os.environ["ORCH_ADDR"], realm=os.environ["ORCH_REALM"])
            runner.run(app, auto_reconnect=True)
        except Exception as ex:
            self.logger.error(str(ex))

    @set_ev_cls(oflw_evt.EventSwitchEnter)
    def _switch_enter(self, ev):
        self.set_datapath(ev.switch.dp)
        self.set_prefix(self.get_datapath().get_dpid())
        db_address, _ = self.get_datapath().dp.address

        self.logger.info("new switch <{i}> has attached to agent <{a}>".format(i=self.get_datapath().get_dpid(),
                                                                               a=self.get_prefix()))

        if check_ovs_service(db_address, port='6640'):
            self.logger.info("the ovsdb service has reached out")
            self.set_ovsdb(db_address, "6640")
        else:
            self.logger.error(
                "enable ovsdb manager in {a} with 'set-manager ptcp:6640'".format(a=db_address))

        mp.set_start_method('spawn')
        self._process = mp.Process(target=self._start_wamp())
        self._process.start()
