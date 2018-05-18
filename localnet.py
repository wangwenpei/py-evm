"""
=============

=============
"""

import asyncio
import logging
from typing import (cast)  # noqa: F401

from eth_keys import (
    keys,
)
from eth_utils import (
    decode_hex,
)

from p2p import ecies
from p2p.constants import (
    HANDSHAKE_TIMEOUT,
)
from p2p.kademlia import Address, Node
from p2p.peer import LESPeer, ETHPeer, handshake


def main():
    """
    Create a Peer instance connected to a local geth instance and log messages exchanged with it.

    Use the following command line to run geth:

        ~/Codes/gohome/bin/geth -vmodule p2p=4,p2p/discv5=0,eth/*=0 \
          -nodekeyhex 45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8 \
          -testnet -lightserv 90
    """

    import argparse
    import signal
    from evm.chains.ropsten import RopstenChain, ROPSTEN_GENESIS_HEADER
    from evm.db.backends.memory import MemoryDB
    from tests.p2p.integration_test_helpers import FakeAsyncChainDB
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s')

    # The default remoteid can be used if you pass nodekeyhex as above to geth.
    nodekey = keys.PrivateKey(decode_hex(
        "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"))
    remoteid = nodekey.public_key.to_hex()
    parser = argparse.ArgumentParser()
    parser.add_argument('-remoteid', type=str, default=remoteid)
    parser.add_argument('-light', action='store_true',
                        help="Connect as a light node")
    args = parser.parse_args()

    peer_class = ETHPeer  # type: ignore
    if args.light:
        peer_class = LESPeer  # type: ignore
    remote = Node(
        keys.PublicKey(decode_hex(args.remoteid)),
        Address('127.0.0.1', 30303, 30303))
    chaindb = FakeAsyncChainDB(MemoryDB())
    chaindb.persist_header(ROPSTEN_GENESIS_HEADER)
    network_id = RopstenChain.network_id
    loop = asyncio.get_event_loop()
    peer = loop.run_until_complete(
        asyncio.wait_for(
            handshake(remote, ecies.generate_privkey(), peer_class, chaindb,
                      network_id),
            HANDSHAKE_TIMEOUT))

    async def request_stuff():
        # Request some stuff from ropsten's block 2440319
        # (https://ropsten.etherscan.io/block/2440319), just as a basic test.
        nonlocal peer
        block_hash = decode_hex(
            '0x59af08ab31822c992bb3dad92ddb68d820aa4c69e9560f07081fa53f1009b152')
        if peer_class == ETHPeer:
            peer = cast(ETHPeer, peer)
            peer.sub_proto.send_get_block_headers(block_hash, 1)
            peer.sub_proto.send_get_block_bodies([block_hash])
            peer.sub_proto.send_get_receipts([block_hash])
        else:
            peer = cast(LESPeer, peer)
            request_id = 1
            peer.sub_proto.send_get_block_headers(block_hash, 1, request_id)
            peer.sub_proto.send_get_block_bodies([block_hash], request_id + 1)
            peer.sub_proto.send_get_receipts(block_hash, request_id + 2)

    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, peer.cancel_token.trigger)

    asyncio.ensure_future(request_stuff())
    loop.run_until_complete(peer.run())
    loop.close()


if __name__ == "__main__":
    main()
