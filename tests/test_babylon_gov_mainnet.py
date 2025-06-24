import base64
import pytest

from pathlib import Path

from ledger_bitcoin import WalletPolicy, MultisigWallet, AddressType, PartialSignature
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException

from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import AddressType
from ragger.navigator import Navigator
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware

from test_utils import bip0340, txmaker

from ragger_bitcoin import RaggerClient
from .instructions import *

tests_root: Path = Path(__file__).parent

# F8697B29D5CF628753FB7B6CFBD99BC9695EA5F2ED4F345E5CE5493F7AADF6CB
# def test_sign_psbt_tr_script_slashing(navigator: Navigator, firmware: Firmware, client:
#                                             RaggerClient, test_name: str):

#     wallet = WalletPolicy(
#         name="Consent to slashing",
#         descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(2,@3/**,@4/**,@5/**,@6/**,@7/**))),older(101)))",
#         keys_info=[
#             "[69846d00/86'/0'/0']xpub661MyMwAqRbcFzGzg1B8LCurCJwMrEkbuRdVRrxnGg3a5fp7zxYhUMbUSbbottr5QvrJfTEkREZkmNWUUgtPrwnXQHQcB2uqWLDDjFgBbDq",
#             "[0ea5efa4/86'/0'/0']xpub6BoyAyZiYkRj2TJ3eDUtq1WLBZSS9y58uNFuZPJQC72JH9PvWQaX3YmJRhHf2AkZFwruN1PaP8eq6EaiWEigcodLzUr66n6AU2owT2GzUz1",
#             "[ff119473/86'/0'/0']xpub661MyMwAqRbcH5ReFP5sPbEaRhaTmNWiJnSHNTq8KsYnMVoPah1junAJcpRXK3PwXDdSyyZK3PBdceQDcXdsSnqNz3qNUfe1KZretUL8rQE", 
#             "xpub661MyMwAqRbcFBGrwjm3fwceERiFTwkCHcXwMehHExpcfazJYA8rtDhe1iHvUGh4vZg7VLkjFSGVJF5Y98j13z5GmsHu8gJQ5FyjLyeXeSb", 
#             "xpub661MyMwAqRbcFo9jx5v9st9BDctiVzzFo6JcTPBgkgGrCho2FgUekiW9xagAkX5EU4RiVMMX6fgCjNtydmM4BePsb1MdrWmTqzg3xRSYfpe", 
#             "xpub661MyMwAqRbcFQRTjQJ5LPCF6eVwM8joLFSN7qRaBRYuQw7P5zsaaqNprFmwoAasuaZBQf8UKhDc4nqJnG4EjPPJ4JqKe5RpY2CkpArSBva", 
#             "xpub661MyMwAqRbcGRp6FX2BYhbLDeb6rVFZsgtYLE2913CdpcZd9E9dJcTakj4cVUaMFLHeEpLTjQ4d74FdAUjT257iNxtn5kkdf6dSuMEeHMQ",
#             "xpub661MyMwAqRbcGL2YHJpMKZGkMewTFmXvirjTRCnoAcEv3wvtQSJtr8hyK5Gg3wTe9vwgxafA3fHRr6ihN2ZAAyaqQA3AvYugjUA2nAhzXb8"
#         ],
#     )

#     wallet_hmac = bytes.fromhex(
#         "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
#     )

#     psbt = PSBT()
#     psbt.deserialize("cHNidP8BAHACAAAAAYgLPFJcxFX5NXIghFYRv7Ts5dEJU3coeny8TnooyoP2AAAAAAD/////AvQBAAAAAAAACWoHYmFieWxvboy5AAAAAAAAIlEgZ6Z7KtDJwyvZaUkytL0QMV6QXqWwkdcvMTT24slOxCAAAAAAAAEBK1DDAAAAAAAAIlEgm6qEu19ofD0FD1s6PaAlVqxT9bYtcT+7fu507LDhKWpCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wMJlhvGU7dciIPfdxpwaTfR18EeEsl4rF/iFE0txjvF7rSCBVkBvo6fnP/UUqQUcCkVUpxQlJKQaqqr8h5xolwIRZ60g5IiWMPqGldrmMMQc2bhe8WXMwtxeWTXVokOTqd7+6e+tIG8TptEERGUg0XV8rsE+r2+88p9IjDHgEH5zUdSZTNBorCChCga7O642DbOu8DJkE7Vbnka/ILmpb8ioBqmeZE/id7ogpeIVFGgrh+N/tdPJhiBVBB0eb0zE8wNM6vPZD4ayMKa6UpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=")


#     result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
#                               instructions=sign_psbt_instruction_slasing(firmware),
#                               testname=test_name)

#     assert len(result) == 1

#     # sighash verified with real transaction
#     sighash0 = bytes.fromhex("BA111E858EED59BA9527273BC8DFB047AE96BE59B6B4EC3769F6C35E5135134C")
#     leaf_hash = bytes.fromhex("1C8F4E4BB85D596BB49BEB4207BC3107CE7058EA027CDE6A43D7C7D72228A557")
#     assert len(result) == 1
#     idx0, partial_sig0 = result[0]
#     assert idx0 == 0
    
#     assert partial_sig0.tapleaf_hash == leaf_hash, "leafhash veriry fail"
    
  
#     assert partial_sig0.pubkey == bytes.fromhex("dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878")
#     assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64]), "signature veriry fail"
