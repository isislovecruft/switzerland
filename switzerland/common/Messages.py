#!/usr/bin/env python

# Message.py -- Switzerland protocol messages.

import types

class Message:
    """
    Message: represents each message that can be sent by Alice or Switzerland
    or both.  We don't instantiate this class for every message on the wire;
    these objects are just used to fill static dicts that the *Link classes
    use to look up message properties.
    """

    def __init__(self, name, arguments, expects_ack, expects_reply, is_reply):
        assert isinstance(name, types.StringType)
        assert isinstance(arguments, types.ListType)

        self.name = name
        self.length = len(arguments) + 1
        self.expects_ack = expects_ack
        self.expects_reply = expects_reply
        self.is_reply = is_reply

        if expects_ack or expects_reply:
            self.length += 1   # for a sequence number

        if is_reply:
            self.length += 1   # for a reply sequence number

alice_in_messages = {}
alice_out_messages = {}
switzerland_in_messages = {}
switzerland_out_messages = {}

# Some syntactic sugar -- concisely construct each message and place it in
# the correct categories.
def _cmsg(name, num_args, expects_ack=False, expects_reply=False,
          is_reply=None):
    """These go in either direction."""

    msg = Message(name, num_args, expects_ack, expects_reply, is_reply)
    alice_in_messages[name] = switzerland_out_messages[name] = msg
    alice_out_messages[name] = switzerland_in_messages[name] = msg

def _amsg(name, num_args, expects_ack=False, expects_reply=False,
          is_reply=None):
    """Alice sends these to Switzerland."""

    msg = Message(name, num_args, expects_ack, expects_reply, is_reply)
    alice_out_messages[name] = msg
    switzerland_in_messages[name] = msg

def _smsg(name, num_args, expects_ack=False, expects_reply=False,
          is_reply=None, assert_len=None):
    """Switzerland sends these to alice."""

    msg = Message(name, num_args, expects_ack, expects_reply, is_reply)
    alice_in_messages[name] = msg
    switzerland_out_messages[name] = msg

# The contents of the arguments below are purely for documentation

# Messages that can be sent in either direction.

_cmsg("ping", [], expects_ack=True)
_cmsg("error-bye", ["details"])
_cmsg("error-cont", ["details"], expects_ack=True)
_cmsg("signoff", [])
_cmsg("ack", ["seq_no"], )     # sort of a special case for not having an is_ack
_cmsg("test", ["alpha", "beta", "gamma"])

# Alice -> Switzerland

_amsg("parameters",
      [{"clock dispersion" : 0.085, "will send actual packets": False}])
_amsg("my-ip", [["my private ip", "my public ip"]], expects_reply=True)
_amsg("active_flows", [["new flows"], ["deleted flows"]])
_amsg("flow_stats", [("flow", {"stat": "value"})])
_amsg("sent", ["flow id", "timestamp", "concatenated hashes"])
_amsg("recd", ["flow id", "timestamp", "concatenated hashes"])
_amsg("fi-context", [{"hash": [("timestamp", "hash", "data")]}], is_reply=True, expects_reply=True)
_amsg("fo-context", [{"hash": [("timestamp", "data")]}], {"hash": ["diff1","diff2"]}, is_reply=True)
_amsg("rst-radar", [[("list", "of"), ("packet", "pairs")]])
_amsg("traceroute", ["destination", "type", "results"])

# Switzerland -> Alice

_smsg("debug-ipid", ["ipid"])
_smsg("public-ip", ["your public ip"], is_reply=True)
_smsg("new-members", [[("ip1", "firewalled", "key"), ("ip2", "firewalled", "key")]], expects_ack=True)

# Other client hangs up.
_smsg("farewell", ["ip"], expects_ack=True)
# Other clients go missing.
_smsg("igcognito", [["list", "of", "ips"]], expects_ack=True)

_smsg("forged-in", ["flow id", [("timestamp", "hash")]], expects_reply=True)
_smsg("forged-out", ["flow id", [["context"]]], expects_reply=True, assert_len=2)
_smsg("forged-details", ["flow id", [("timestamp", "context", "report")]], is_reply=True)

# The other side isn't reporting this flow in a way that allows us to match
# them.
_smsg("dangling-flow", ["flow id", "opening hash"])

# The other side isn't reporting this flow in a way that allows us to match
# them.
_smsg("flow-status", ["string"])

# vim: set ts=4
