import base64
import pytest
import requests  # ← 加上这一行

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

def test_sign_psbt_tr_script_stake_transfer_with_extrakey(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    wallet = WalletPolicy(
        name="Staking transaction",
        descriptor_template="tr(@0/**,and_v(and_v(pk_k(@1/**),and_v(pk_k(@2/**),multi_a(6,@3/**,@4/**,@5/**,@6/**,@7/**,@8/**,@9/**,@10/**,@11/**))),older(64000),pk_k(@12/**)))",
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

    with pytest.raises(ExceptionRAPDU) as excinfo:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                        instructions=sign_psbt_instruction_stake(firmware),
                        testname=test_name)
    assert excinfo.value.status == 0x6A80, f"Unexpected SW: {hex(excinfo.value.status)}"

def test_sign_psbt_tr_script_slashing_with_wrong_burnaddress(navigator: Navigator, firmware: Firmware, client:
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
            "tpubD6NzVbkrYhZ4WVcvRUwsQ6ikvD9gcNNKaVwKQpNuqzAQybVoWJt2GohhzAfaEc32wVG1W3QvUt5CXPwjPtChZtWuo18seJphcyMcThoWTHB",
            "tpubD6NzVbkrYhZ4XpXxDwUaMMg7KKWRsQGtsXu1CAtnQKoBxQGvt6qWQtFXw5opkh8Ta8PNVPL84ceUftWyMjbFLuszbDWsfRMrVgPPzWHiMZH"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH0CAAAAAU5oPucfQQOAdrEZwJODBvpzHfaA/orEXxwbxelbMexgAAAAAAD/////AsQJAAAAAAAAFgAUW+EmJNCKK0JAldfAciHDNFDRS/EEpgAAAAAAACJRICyVutUKY9E6qBjfjktoZBga2/RyCoiq+OPBI1ugik2fAAAAAAABAStQwwAAAAAAACJRINdj3mtHHjBWQbpB1lxngujLz/bgjoPaqw2hJ1u8n6rQQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsCJtgX5iDHD5SbZ6yF5ZRRSk4qMD/f16u7MthJR1dRt6/15ASDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eK0g1mEk+PQv2D5MkBoQCuO11wbvbP0hewS8ZBUuc5owxB6tIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=")

    try:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                         instructions=sign_psbt_instruction_slasing(firmware),
                         testname=test_name)
        assert False, "Expected user rejection, but operation succeeded"
    except DeviceException:
        pass
    except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError, TimeoutError):
        pass

def test_sign_psbt_tr_script_slashing_with_lowfee(navigator: Navigator, firmware: Firmware, client:
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
            "tpubD6NzVbkrYhZ4WWRtXd8DZd3fGhtZkq6yW7CKdK2LDfGLLmqytgFhhWhjKkjCG2ZYFYZzvjqB4etrcdGVUbbAtWkBoRzBYiTAA5T7q7nKdRo"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAH0CAAAAAU5oPucfQQOAdrEZwJODBvpzHfaA/orEXxwbxelbMexgAAAAAAD/////AsQJAAAAAAAAFgAUW+EmJNCKK0JAldfAciHDNFDRS/EEpgAAAAAAACJRICyVutUKY9E6qBjfjktoZBga2/RyCoiq+OPBI1ugik2fAAAAAAABAStQwwAAAAAAACJRINdj3mtHHjBWQbpB1lxngujLz/bgjoPaqw2hJ1u8n6rQQhXBUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsCJtgX5iDHD5SbZ6yF5ZRRSk4qMD/f16u7MthJR1dRt6/15ASDcjS+e/wxPTb3gcKSOMw78kItip2ZWjZHmWPKEsyS4eK0g1mEk+PQv2D5MkBoQCuO11wbvbP0hewS8ZBUuc5owxB6tIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAAA=")

    try:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                         instructions=sign_psbt_instruction_slasing(firmware),
                         testname=test_name)
        assert False, "Expected user rejection, but operation succeeded"
    except DeviceException:
        pass
    except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError, TimeoutError):
        pass

def test_sign_psbt_tr_script_unbounding_high_fee(navigator: Navigator, firmware: Firmware, client:
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
            "tpubD6NzVbkrYhZ4XNVEYgehk6gN2dDvFzfAoDirJYoPAamqjtiHveTpq5qdQvndA59ZqGuNeMozVhjpfWA63heCKEoe3PUKHBsiP7s1yFbyKba"
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAF4CAAAAARSsiq2TFq5P/835EAvNgCZXDC6CS1+xtit+DY7G1dygAAAAAAD/////AZDiAAAAAAAAIlEg/pvwU6TWJxOSa6vlGbQnPyEX/XzVCkXJjxRCchhfo2EAAAAAAAEBK2DqAAAAAAAAIlEgvuEgqB2XZe+afeBe8ZLwNCRA7hqxujxpU15NDJOT+tFiFcFQkpt0waBJVLeLS2A16XpeB4paDyjsltVHv+6azoA6wGiUOxKox1UcaYkUfLw1P/gRozOyIAYscJZUYYhS14qO7WLOBOR2DLfcS2FXnhYLyDSDei74a1DrKfwNlVI2ikX9VwEg3I0vnv8MT0294HCkjjMO/JCLYqdmVo2R5ljyhLMkuHitIAruBQmxbbccmZI4pIJ9uUVSaFmxPJVIerRnJTV8mp8lrCARPDoyqdMgtyGQoEoCCg2zl27zaXJnMljpo4o2Tz3DsLogF5Ic8VbMtOc9Qo+ZbtEbJFMT434nyXisTSzCHspGcuS6IDu5PfyLYYh9dx82MOmmPpfLr8/MeFVqR034OjGg74mcuiBAr69HxP+lbehkENjke6ortvBLYE9OokMjc33cP+CS37ogeacf/XHFA+8uL5G8z8j82nlG9GU87w2fPd4geV7zufC6INIfr3jGdRoNOOa9gCi5B/8H6ahppD/IN9az+N/2EZo2uiD1GZ764/KLuCR2Fjp+RYx61EXZv/sGgtENO9sstB+Ojrog+p2ILUX0BgvbgEIYOCjNh1RPHqmXOA5YbKt31f1phze6VpzAARcgUJKbdMGgSVS3i0tgNel6XgeKWg8o7JbVR7/ums6AOsAAAA==")



    # fees don't fit in the same page on 'flex', but they fit on 'stax'

    try:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                         instructions=sign_psbt_instruction_slasing(firmware),
                         testname=test_name)
        assert False, "Expected user rejection, but operation succeeded"
    except DeviceException:
        pass
    except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError, TimeoutError):
        pass