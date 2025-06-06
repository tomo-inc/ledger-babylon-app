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


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt

    #slasing
    # in audit doc: and_v(vc:pk_k(staker_pk), and_v(vc:pk_k(finalityprovider_pk),multi_a(covenant_threshold, covenant_pk1, ..., covenant_pkn)))
    #tr(@0/**,and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**))))
    
    #unbounding
    #in audit doc:  and_v(vc:pk_k(staker_pk), multi_a(covenant_threshold,covenant_pk1, ..., covenant_pkn))
    #tr(@0/**,and_v(pk_k(@1/**), multi_a(6, @2/**,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**)))
    
    #timelock
    #in audit doc: and_v(vc:pk_k(staker_pk), older(timelock_blocks))
    #tr(@0/**,and_v(pk_k(@1/**), older(12690)))


def test_sign_psbt_tr_script_slashing(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):

    wallet = WalletPolicy(
        name="Consent to slashing",
        descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**,@12/**,@13/**))),older(1008)))",
        keys_info=[
            "[69846d00/86'/1'/0']tpubD6NzVbkrYhZ4WNLDZARxRfzGzvp9Lnm88oGRLmoTSPWNg3uuE6F4xBdmcEqUxs2ovExCUqFBjvF8QkjawKp1KRp6wtFDptzPbBPwQ9LMeY1",
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
            "[ff119473/86'/1'/0']tpubD6NzVbkrYhZ4Yt3Vn3Naxxfg8LpfnAkUBVsm2VLFDXCWekWMsZSvKjpeWM9AVgnQxUjc9fWS7gW7Vvoy2kXbgGBc6KxTGoMP7W688gzhyKe", 
            "tpubD6NzVbkrYhZ4WwrfC9BkfdDF7YNk8dXmJ7acsTTtR3C6hr8qvsb2K7Dp42uMsVAW4L8Qc1RakiTDZg1ywXDNUxNBRCkp3dS7yj7x7VMPVqz", 
            "tpubD6NzVbkrYhZ4Xuv92CZucpRA6ou9tKpe73EomdBVJ9PkXKirJEAkedwKTgKR8bhe4Pp1zJNmK71LbWPattjZqShzT3go658xc5FQiLRZQFr", 
            "tpubD6NzVbkrYhZ4XtngEHGMzyYcYY9S9dhpe5awQW7rMfDs247YPe4UkjKu3zUT5gLreiDMCsq1RX4BvPaP9PWhrFYo3sk2M1HVjdHjMWiC8pn", 
            "tpubD6NzVbkrYhZ4XgSQ8NsumcA7iHSCou5Vegcf8AK7mezeUQUKJeS2trsPqaYeuAM7FEizZEFcuQ7aWf27CdBL1E7kZEv9rwDrsq18oov8H7A", 
            "tpubD6NzVbkrYhZ4Ysn5e6UVJLDVowAks2RuUbyaNM4NLNvU2PaPSuvmFB3NeYUDNf5EF1C8pGYCjBWKtGMqbD6HiYj4xyWhFSAxucQ26EGED7H", 
            "tpubD6NzVbkrYhZ4WZ9ozPNtBTh7bNtczM2CmHkg7SYSQx7DUTn4YjeFK4SqBgFRqjuZC1XTnxDqJaqPNcMxSFjrLMZgGU1dkF4THyXdyP2iHa9", 
            "tpubD6NzVbkrYhZ4YWPuHMubgo31Rn2oBG2EuH7eFVpTnyQzhu3upESECW8HyouyLXUXsRVwgDja9aoFggnhiX6zLEWiVrJWfMrbRH5qaSdEZg7", 
            "tpubD6NzVbkrYhZ4XVW9QtYpXNdtQsCTLZZCoKmnzPpwh9F54VmjxHciynJA7qqf2rfeEuqvDNuaPG4g6F9TdjeUyhFWbbeNyhVnJGNjhxaESqT", 
            "tpubD6NzVbkrYhZ4WiZ659T6qE19WFEa7LD2ZFYD1peKszT6Xqkdrvkp7Gkyk7PRRW2Jtm5fgUSWJsvF6rq9yDt8muoa9HB5mC8UGayBf8arZvW",
            "tpubD6NzVbkrYhZ4YQYKM9N9ySSZbVmvJGRYGxcWtKodjaz1NygcwFHeo6uCedYvggqNrP2wEZcUvYfoBixDgzZpZ9rhRFdGrRnioFKLYM4Ze4J",
            "tpubD6NzVbkrYhZ4XpXxDwUaMMg7KKWRsQGtsXu1CAtnQKoBxQGvt6qWQtFXw5opkh8Ta8PNVPL84ceUftWyMjbFLuszbDWsfRMrVgPPzWHiMZH"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH0CAAAAAU5oPucfQQOAdrEZwJODBvpzHfaA/orEXxwbxelbMexgAAAAAAD/////AsQJAAAAAAAAFgAUW+EmJNCKK0JAldfAciHDNFDRS/EEpgAAAAAAACJRICyVutUKY9E6qBjfjktoZBga2/RyCoiq+OPBI1ugik2fAAAAAAABAStQwwAAAAAAACJRINdj3mtHHjBWQbpB1lxngujLz/bgjoPaqw2hJ1u8n6rQQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsCJtgX5iDHD5SbZ6yF5ZRRSk4qMD/f16u7MthJR1dRt6/15ASDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eK0g1mEk+PQv2D5MkBoQCuO11wbvbP0hewS8ZBUuc5owxB6tIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=")


    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_slasing(firmware),
                              testname=test_name)

    assert len(result) == 1

    # sighash verified with real transaction
    sighash0 = bytes.fromhex("BA111E858EED59BA9527273BC8DFB047AE96BE59B6B4EC3769F6C35E5135134C")
    leaf_hash = bytes.fromhex("ed429f93af8bb724a9f5066248b32d945fdd1c12f7f59a33f4f83b6565716750")
    assert len(result) == 1
    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    
    assert partial_sig0.tapleaf_hash == leaf_hash, "leafhash veriry fail"
    
  
    assert partial_sig0.pubkey == bytes.fromhex("dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878")
    assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64]), "signature veriry fail"

def test_sign_psbt_tr_script_slashing_unbounding(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):

    wallet = WalletPolicy(
        name="Consent to unbonding slashing",
        descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**,@12/**,@13/**))),older(1008)))",
        keys_info=[
            "[69846d00/86'/1'/0']tpubD6NzVbkrYhZ4WNLDZARxRfzGzvp9Lnm88oGRLmoTSPWNg3uuE6F4xBdmcEqUxs2ovExCUqFBjvF8QkjawKp1KRp6wtFDptzPbBPwQ9LMeY1",
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
            "[ff119473/86'/1'/0']tpubD6NzVbkrYhZ4Yt3Vn3Naxxfg8LpfnAkUBVsm2VLFDXCWekWMsZSvKjpeWM9AVgnQxUjc9fWS7gW7Vvoy2kXbgGBc6KxTGoMP7W688gzhyKe", 
            "tpubD6NzVbkrYhZ4WwrfC9BkfdDF7YNk8dXmJ7acsTTtR3C6hr8qvsb2K7Dp42uMsVAW4L8Qc1RakiTDZg1ywXDNUxNBRCkp3dS7yj7x7VMPVqz", 
            "tpubD6NzVbkrYhZ4Xuv92CZucpRA6ou9tKpe73EomdBVJ9PkXKirJEAkedwKTgKR8bhe4Pp1zJNmK71LbWPattjZqShzT3go658xc5FQiLRZQFr", 
            "tpubD6NzVbkrYhZ4XtngEHGMzyYcYY9S9dhpe5awQW7rMfDs247YPe4UkjKu3zUT5gLreiDMCsq1RX4BvPaP9PWhrFYo3sk2M1HVjdHjMWiC8pn", 
            "tpubD6NzVbkrYhZ4XgSQ8NsumcA7iHSCou5Vegcf8AK7mezeUQUKJeS2trsPqaYeuAM7FEizZEFcuQ7aWf27CdBL1E7kZEv9rwDrsq18oov8H7A", 
            "tpubD6NzVbkrYhZ4Ysn5e6UVJLDVowAks2RuUbyaNM4NLNvU2PaPSuvmFB3NeYUDNf5EF1C8pGYCjBWKtGMqbD6HiYj4xyWhFSAxucQ26EGED7H", 
            "tpubD6NzVbkrYhZ4WZ9ozPNtBTh7bNtczM2CmHkg7SYSQx7DUTn4YjeFK4SqBgFRqjuZC1XTnxDqJaqPNcMxSFjrLMZgGU1dkF4THyXdyP2iHa9", 
            "tpubD6NzVbkrYhZ4YWPuHMubgo31Rn2oBG2EuH7eFVpTnyQzhu3upESECW8HyouyLXUXsRVwgDja9aoFggnhiX6zLEWiVrJWfMrbRH5qaSdEZg7", 
            "tpubD6NzVbkrYhZ4XVW9QtYpXNdtQsCTLZZCoKmnzPpwh9F54VmjxHciynJA7qqf2rfeEuqvDNuaPG4g6F9TdjeUyhFWbbeNyhVnJGNjhxaESqT", 
            "tpubD6NzVbkrYhZ4WiZ659T6qE19WFEa7LD2ZFYD1peKszT6Xqkdrvkp7Gkyk7PRRW2Jtm5fgUSWJsvF6rq9yDt8muoa9HB5mC8UGayBf8arZvW",
            "tpubD6NzVbkrYhZ4YQYKM9N9ySSZbVmvJGRYGxcWtKodjaz1NygcwFHeo6uCedYvggqNrP2wEZcUvYfoBixDgzZpZ9rhRFdGrRnioFKLYM4Ze4J",
            "tpubD6NzVbkrYhZ4XpXxDwUaMMg7KKWRsQGtsXu1CAtnQKoBxQGvt6qWQtFXw5opkh8Ta8PNVPL84ceUftWyMjbFLuszbDWsfRMrVgPPzWHiMZH"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH0CAAAAAU5oPucfQQOAdrEZwJODBvpzHfaA/orEXxwbxelbMexgAAAAAAD/////AsQJAAAAAAAAFgAUW+EmJNCKK0JAldfAciHDNFDRS/EEpgAAAAAAACJRICyVutUKY9E6qBjfjktoZBga2/RyCoiq+OPBI1ugik2fAAAAAAABAStQwwAAAAAAACJRINdj3mtHHjBWQbpB1lxngujLz/bgjoPaqw2hJ1u8n6rQQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsCJtgX5iDHD5SbZ6yF5ZRRSk4qMD/f16u7MthJR1dRt6/15ASDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eK0g1mEk+PQv2D5MkBoQCuO11wbvbP0hewS8ZBUuc5owxB6tIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=")


    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_slasing(firmware),
                              testname=test_name)

    assert len(result) == 1

    # sighash verified with real transaction
    sighash0 = bytes.fromhex("BA111E858EED59BA9527273BC8DFB047AE96BE59B6B4EC3769F6C35E5135134C")
    leaf_hash = bytes.fromhex("ed429f93af8bb724a9f5066248b32d945fdd1c12f7f59a33f4f83b6565716750")
    assert len(result) == 1
    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    
    assert partial_sig0.tapleaf_hash == leaf_hash, "leafhash veriry fail"
    
  
    assert partial_sig0.pubkey == bytes.fromhex("dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878")
    assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64]), "signature veriry fail"

def test_sign_psbt_tr_script_stake_transfer(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    wallet = WalletPolicy(
        name="Staking transaction",
        descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**))),older(64000)))",
         keys_info=[
            "[69846d00/86'/1'/0']tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
            "[ff119473/86'/1'/0']tpubD6NzVbkrYhZ4Yt3Vn3Naxxfg8LpfnAkUBVsm2VLFDXCWekWMsZSvKjpeWM9AVgnQxUjc9fWS7gW7Vvoy2kXbgGBc6KxTGoMP7W688gzhyKe", 
            "tpubD6NzVbkrYhZ4WwrfC9BkfdDF7YNk8dXmJ7acsTTtR3C6hr8qvsb2K7Dp42uMsVAW4L8Qc1RakiTDZg1ywXDNUxNBRCkp3dS7yj7x7VMPVqz", 
            "tpubD6NzVbkrYhZ4Xuv92CZucpRA6ou9tKpe73EomdBVJ9PkXKirJEAkedwKTgKR8bhe4Pp1zJNmK71LbWPattjZqShzT3go658xc5FQiLRZQFr", 
            "tpubD6NzVbkrYhZ4XtngEHGMzyYcYY9S9dhpe5awQW7rMfDs247YPe4UkjKu3zUT5gLreiDMCsq1RX4BvPaP9PWhrFYo3sk2M1HVjdHjMWiC8pn", 
            "tpubD6NzVbkrYhZ4XgSQ8NsumcA7iHSCou5Vegcf8AK7mezeUQUKJeS2trsPqaYeuAM7FEizZEFcuQ7aWf27CdBL1E7kZEv9rwDrsq18oov8H7A", 
            "tpubD6NzVbkrYhZ4Ysn5e6UVJLDVowAks2RuUbyaNM4NLNvU2PaPSuvmFB3NeYUDNf5EF1C8pGYCjBWKtGMqbD6HiYj4xyWhFSAxucQ26EGED7H", 
            "tpubD6NzVbkrYhZ4WZ9ozPNtBTh7bNtczM2CmHkg7SYSQx7DUTn4YjeFK4SqBgFRqjuZC1XTnxDqJaqPNcMxSFjrLMZgGU1dkF4THyXdyP2iHa9", 
            "tpubD6NzVbkrYhZ4YWPuHMubgo31Rn2oBG2EuH7eFVpTnyQzhu3upESECW8HyouyLXUXsRVwgDja9aoFggnhiX6zLEWiVrJWfMrbRH5qaSdEZg7", 
            "tpubD6NzVbkrYhZ4XVW9QtYpXNdtQsCTLZZCoKmnzPpwh9F54VmjxHciynJA7qqf2rfeEuqvDNuaPG4g6F9TdjeUyhFWbbeNyhVnJGNjhxaESqT", 
            "tpubD6NzVbkrYhZ4WiZ659T6qE19WFEa7LD2ZFYD1peKszT6Xqkdrvkp7Gkyk7PRRW2Jtm5fgUSWJsvF6rq9yDt8muoa9HB5mC8UGayBf8arZvW"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAIkCAAAAAQoDdUgOA5oDhvrH0NWZTa/GJzvd4UhFIbmbOiWufc84AAAAAAD/////AlDDAAAAAAAAIlEg12Pea0ceMFZBukHWXGeC6MvP9uCOg9qrDaEnW7yfqtAcAi0AAAAAACJRIHQO5k5FLjuu4SewPBlbzCGtPt3tLvJsWvSD2cVjBNHlAAAAAAABASvAxi0AAAAAACJRIHQO5k5FLjuu4SewPBlbzCGtPt3tLvJsWvSD2cVjBNHlARcg3I0vnv8MT0294HCkjjMO/JCLYqdmVo2R5ljyhLMkuHgAAAA=")



    # fees don't fit in the same page on 'flex', but they fit on 'stax' instructions=sign_psbt_instruction_approve(firmware),

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_stake(firmware),
                              testname=test_name)

    assert len(result) == 1

    # # sighash verified with real transaction
    sighash0 = bytes.fromhex("672C460A4AB491DD3B70BC5E35D4796683AF95B11F68D4667A8963CBC52A3CDF")
    assert len(result) == 1
    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    
    assert partial_sig0.tapleaf_hash is None, "leaf hash is not None"
    
  
def test_sign_psbt_tr_script_unbounding(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):

    wallet = WalletPolicy(
        name="Unbonding",
        descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**,@12/**))),older(1008)))",
        keys_info=[
           "[69846d00/86'/1'/0']tpubD6NzVbkrYhZ4XWi3SqSnoi6YERXhkUcjv6qJxF8Ujdk4HDY6oyr6gxA56UVRr3TbnwK9pPchZgVzh9RwAgLMAvPadvGBdjVDqoz5DwDjMVP",
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
            "[ff119473/86'/1'/0']tpubD6NzVbkrYhZ4YaL8V9jDXSVBuoXYZ8fM4M8ykTRbipQ1wGCm1FCbvZfQaZUZxkxEwF3LJbiMNo6TCB6uU9hBvEZvuEqhKkExeTxmwMLwCtw", 
            "tpubD6NzVbkrYhZ4WwrfC9BkfdDF7YNk8dXmJ7acsTTtR3C6hr8qvsb2K7Dp42uMsVAW4L8Qc1RakiTDZg1ywXDNUxNBRCkp3dS7yj7x7VMPVqz", 
            "tpubD6NzVbkrYhZ4Xuv92CZucpRA6ou9tKpe73EomdBVJ9PkXKirJEAkedwKTgKR8bhe4Pp1zJNmK71LbWPattjZqShzT3go658xc5FQiLRZQFr", 
            "tpubD6NzVbkrYhZ4XtngEHGMzyYcYY9S9dhpe5awQW7rMfDs247YPe4UkjKu3zUT5gLreiDMCsq1RX4BvPaP9PWhrFYo3sk2M1HVjdHjMWiC8pn", 
            "tpubD6NzVbkrYhZ4XgSQ8NsumcA7iHSCou5Vegcf8AK7mezeUQUKJeS2trsPqaYeuAM7FEizZEFcuQ7aWf27CdBL1E7kZEv9rwDrsq18oov8H7A", 
            "tpubD6NzVbkrYhZ4Ysn5e6UVJLDVowAks2RuUbyaNM4NLNvU2PaPSuvmFB3NeYUDNf5EF1C8pGYCjBWKtGMqbD6HiYj4xyWhFSAxucQ26EGED7H", 
            "tpubD6NzVbkrYhZ4WZ9ozPNtBTh7bNtczM2CmHkg7SYSQx7DUTn4YjeFK4SqBgFRqjuZC1XTnxDqJaqPNcMxSFjrLMZgGU1dkF4THyXdyP2iHa9", 
            "tpubD6NzVbkrYhZ4YWPuHMubgo31Rn2oBG2EuH7eFVpTnyQzhu3upESECW8HyouyLXUXsRVwgDja9aoFggnhiX6zLEWiVrJWfMrbRH5qaSdEZg7", 
            "tpubD6NzVbkrYhZ4XVW9QtYpXNdtQsCTLZZCoKmnzPpwh9F54VmjxHciynJA7qqf2rfeEuqvDNuaPG4g6F9TdjeUyhFWbbeNyhVnJGNjhxaESqT", 
            "tpubD6NzVbkrYhZ4WiZ659T6qE19WFEa7LD2ZFYD1peKszT6Xqkdrvkp7Gkyk7PRRW2Jtm5fgUSWJsvF6rq9yDt8muoa9HB5mC8UGayBf8arZvW",
            "tpubD6NzVbkrYhZ4Y8DPjVoSXUc7gn37FA2zGVKkmkqwWWzooEbbUf9yzaNoZ7MTaSQswqUbaAB2am7UYHDJktQQ4R38TknUc5ZvKRkSYCM1XZd"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAF4CAAAAARSsiq2TFq5P/835EAvNgCZXDC6CS1+xtit+DY7G1dygAAAAAAD/////AZDiAAAAAAAAIlEg/pvwU6TWJxOSa6vlGbQnPyEX/XzVCkXJjxRCchhfo2EAAAAAAAEBK2DqAAAAAAAAIlEgvuEgqB2XZe+afeBe8ZLwNCRA7hqxujxpU15NDJOT+tFiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wGiUOxKox1UcaYkUfLw1P/gRozOyIAYscJZUYYhS14qO7WLOBOR2DLfcS2FXnhYLyDSDei74a1DrKfwNlVI2ikX9VwEg3I0vnv8MT0294HCkjjMO/JCLYqdmVo2R5ljyhLMkuHitIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA==")



    # fees don't fit in the same page on 'flex', but they fit on 'stax'

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_unbounding(firmware),
                              testname=test_name)

    assert len(result) == 1

    # sighash verified with real transaction
    sighash0 = bytes.fromhex("78FB17A1258D8088DF74C8512F1845EDF8B026EFB814B971C7BC2971CCD9C2A8")
    leaf_hash = bytes.fromhex("b537e46643bb97918f166ca08893e75a4e5044e92abc0d48259b348b04f4ad5f")
    assert len(result) == 1
    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    
    assert partial_sig0.tapleaf_hash == leaf_hash, "leafhash veriry fail"
    
  
    assert partial_sig0.pubkey == bytes.fromhex("dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878")
    assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64]), "signature veriry fail"
    

def test_sign_psbt_tr_script_withdraw(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):

    wallet = WalletPolicy(
        name="Withdraw",
        descriptor_template="tr(@0/**,and_v(pk_k(@1/**),older(1008)))",
        keys_info=[
            "[69846d00/86'/1'/0']tpubD6NzVbkrYhZ4YBJ67CpMGf2s79RA5Z9nQCKwTp7LYAzyJ8RfLjMTsTnQNSAvCSchaNH6AeCMRL6nXnjc1Y9YMJfV6VBKbaLEzQCqtqN4iAC",
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAF4CAAAAAeH2BxZtWBxqa5e1h7G0LZ7JANIrlRdqkdyObGHed2D3AAAAAADwAwAAAWC6AAAAAAAAIlEgdA7mTkUuO67hJ7A8GVvMIa0+3e0u8mxa9IPZxWME0eUAAAAAAAEBK4C7AAAAAAAAIlEgBSZ/XUbQ9Yp+rjB4isu1kF9Bxmw5L+EimM9U7tEzOMNCFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wE/2PBlmrPya/P2SJEn+52lqOKw5Js4JbbljP90EMMqbJyDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eK0C8AOywAEXIFCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrAAAA=")



    # fees don't fit in the same page on 'flex', but they fit on 'stax'

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_withdraw(firmware),
                              testname=test_name)

    assert len(result) == 1

    # sighash verified with real transaction
    sighash0 = bytes.fromhex("5B0C89BF47EEA206B8512E2386278ECD8588CA6EF0C4D460DDAE57A0BC53F571")
    leaf_hash = bytes.fromhex("28be7913bb2c3a1cb55f071af09fd841e2c9fcac044e23d6089c9fe873ceccfa")
    assert len(result) == 1
    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    
    assert partial_sig0.tapleaf_hash == leaf_hash, "leafhash veriry fail"
    
  
    assert partial_sig0.pubkey == bytes.fromhex("dc8d2f9eff0c4f4dbde070a48e330efc908b62a766568d91e658f284b324b878")
    assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64]), "signature veriry fail"


#     # BIP-0322 test
#     # PADDING MESSAGE
#     # len 1 byte || hex of message || (32 - len - 1)*0xFC
def test_sign_psbt_bip322_message_display(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    #  script pubkey = 740ee64e452e3baee127b03c195bcc21ad3edded2ef26c5af483d9c56304d1e5
    #  bbn1dppj9xellvzrh7x60vft4u8cpkyrvv3camt8ps --> 6843229b3ffb043bf8da7b12baf0f80d88363238
    #  https://www.bech32converter.com/
    #  146843229b3ffb043bf8da7b12baf0f80d88363238fcfcfcfcfcfcfcfcfcfcfc

    wallet = WalletPolicy(
        "Sign message",
        "tr(@0/**,and_v(pk_k(@1/**),pk_k(@2/**)))",
         [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U",
            "[83871619/86'/1'/0']tpubD6NzVbkrYhZ4YgAmhRQVWifGGFVzYnFBwTzt1rppUvhGquRV2a2iMX8kP6aKestNhrr7eynAKpJHx7CGXXr6XM4k1Y64Ym7pqsXbds1t6jW",
            "[25270417/86'/1'/0']tpubD6NzVbkrYhZ4YkMn2vxCprkptChmVi9PDL2LeceaonJm71Rqg5TPC7UexzfFVRah3YegACuusqkDQQdCYCAJNiNFkzasVh8XBD6bQsumurc"
    ]
    )
    
    psbt_b64 = "cHNidP8BAD0AAAAAAax33wJvai3ohYqdkcV8Gw1exs19JDS36wHEKb1fWRgYAAAAAAAAAAAAAQAAAAAAAAAAAWoAAAAAAAEBKwAAAAAAAAAAIlEgdA7mTkUuO67hJ7A8GVvMIa0+3e0u8mxa9IPZxWME0eUhFtyNL57/DE9NveBwpI4zDvyQi2KnZlaNkeZY8oSzJLh4GQD1rML9VgAAgAEAAIAAAACAAAAAAAAAAAABFyDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eAAA"
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    hww_sigs = client.sign_psbt(psbt, wallet, None, navigator,
                                instructions=sign_psbt_instruction_message(firmware),
                                testname=test_name)

    assert len(hww_sigs) == 1

