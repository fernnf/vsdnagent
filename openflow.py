import os

from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
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


class OFLWController(object):
    def __init__(self, dp):
        self.dp = dp

    def get_dpid(self):
        return dpid_to_str(self.dp.id)

    def _send_mod(self, out_port, match, inst, cmd):
        cookie = cookie_mask = 0
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 0
        buffer_id = PROTO.OFP_NO_BUFFER
        out_group = PROTO.OFPG_ANY
        flags = 0

        req = PARSER.OFPFlowMod(datapath=self.dp,
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

        return self.dp.send_msg(req)

    def rule_link_port(self, in_port, out_port, vlan_id, cmd, by_pass=False):
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

        def apply_rules_ingress():
            ii, mi = rule_ingress()
            ing = self._send_mod(int(out_port), mi, ii, mod_cmd)
            if not ing:
                raise ValueError("error to apply ingress rules")

        def apply_rules_egress():
            ie, me = rule_egress()
            egr = self._send_mod(int(in_port), me, ie, mod_cmd)
            if not egr:
                raise ValueError("error to apply egress rules")

        if self.dp.is_active():
            apply_rules_ingress()
            apply_rules_egress()
        else:
            raise ValueError("the switch is not available")
