# February 2017, Norio Nakamoto
# Copyright (c) 2017 by cisco Systems, Inc.
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.+


import socket
import logging
from select import select
from ncclient.transport.ssh import SSHSession
from ncclient.transport.errors import SessionCloseError, TransportError
from ncclient.xml_ import *

logger = logging.getLogger("ncclient.transport.third_party.cisco.tcp")
logger.setLevel(logging.WARNING)

BUF_SIZE = 4096
# v1.0: RFC 4742
MSG_DELIM = "]]>]]>"
# v1.1: RFC 6242
END_DELIM = '\n##\n'
TICK = 0.1

'''
Example:
with manager.connect(host="localhost", port=10, transport="tcp") as m:
    c = m.get_config(source='running').data_xml
        print c
'''
class TCPSession(SSHSession):

    "Implements a TCP session."

    def __init__(self, device_handler):
        SSHSession.__init__(self, device_handler)
        self._socket = None

    def close(self):
        self._socket.close()
        self._connected = False

    def connect(self, host, port, timeout=None):
        """
        Connect via TCP and initialize the session.

        *host* is the hostname or IP address to connect to.

        *port* is the port number server side is listening on.

        *timeout* is an optional timeout for socket connect.

        """

        sock = None
        for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, 
                                      socket.SOCK_STREAM, socket.IPPROTO_TCP):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(timeout)
            except socket.error:
                continue
            try:
                sock.connect(sa)
            except socket.error:
                sock.close()
                continue
            break
        else:
            logger.error("Could not open socket to %s:%s" % (host, port))
            raise TransportError("Could not open socket to %s:%s" % (host, port))

        self._socket = sock
        self._connected = True
        self._post_connect()
        logger.debug("Connected to the host")
        return

    def run(self):
        sock = self._socket
        q = self._q

        def start_delim(data_len): return '\n#%s\n'%(data_len)

        try:
            while True:
                """
                select on the socket object.
                If the socket is in read ready stage, move on.
                will wakeup evey TICK seconds to check if something to send, 
                more if something to read (due to select returning chan in
                readable list)
                """
                r, w, e = select([sock], [], [], TICK)
                if r:
                    data = sock.recv(BUF_SIZE)
                    if data:
                        self._buffer.write(data)
                        if self._server_capabilities:
                            if ('urn:ietf:params:netconf:base:1.1' in self._server_capabilities and 
                                'urn:ietf:params:netconf:base:1.1' in self._client_capabilities): 
                                self._parse11()
                            elif ('urn:ietf:params:netconf:base:1.0' in self._server_capabilities or 
                                  'urn:ietf:params:netconf:base:1.0' in self._client_capabilities):
                                self._parse10()
                            else:
                                raise Exception

                        else: self._parse10() # HELLO msg uses EOM markers.
                    else:
                        raise SessionCloseError(self._buffer.getvalue())
                if not q.empty():
                    logger.debug("Sending message")
                    data = q.get()
                    try:
                        # send a HELLO msg using v1.0 EOM markers.
                        validated_element(data, tags='{urn:ietf:params:xml:ns:netconf:base:1.0}hello')
                        data = "%s%s"%(data, MSG_DELIM)
                    except XMLError:
                        # this is not a HELLO msg
                        # we publish v1.1 support
                        if 'urn:ietf:params:netconf:base:1.1' in self._client_capabilities:
                            if self._server_capabilities:
                                if 'urn:ietf:params:netconf:base:1.1' in self._server_capabilities:
                                    # send using v1.1 chunked framing
                                    data = "%s%s%s"%(start_delim(len(data)), data, END_DELIM)
                                elif 'urn:ietf:params:netconf:base:1.0' in self._server_capabilities:
                                    # send using v1.0 EOM markers
                                    data = "%s%s"%(data, MSG_DELIM)
                                else:
                                    raise Exception
                            else:
                                logger.debug('HELLO msg was sent, but server capabilities are still not known')
                                raise Exception
                        # we publish only v1.0 support
                        else:
                            # send using v1.0 EOM markers
                            data = "%s%s"%(data, MSG_DELIM)
                    finally:
                        logger.debug("Sending: %s", data)
                        while data:
                            n = sock.send(data)
                            if n <= 0:
                                raise SessionCloseError(self._buffer.getvalue(), data)
                            data = data[n:]
        except Exception as e:
            logger.debug("Broke out of main loop, error=%r", e)
            self.close()
            self._dispatch_error(e)
