from bulwark import kdf
from bulwark.shared import Header, KDF

SALT = b"0123456789abcdef0123456789abcdef"
PASSWORD = b"password"

NORMAL_MASTER_KEY = bytes.fromhex(
    "707d0a0a6e2489c5a6b9d2745af274b23e380176033fcfa8194913b08b1fa97268430a884e84a597f6105c089335aa18fe162b2880084df74996d6d39a78be53"
)
OVERKILL_MASTER_KEY = bytes.fromhex(
    "99bd5d8f1d3bfc25f31d8728f4d62bbb8a60ff21cf0bcec4933e597c7d7109f6f4fbf3d7b21ceb292c472db29ea53417c143c6e79bcf93556d9307c07aee1a3d"
)

NORMAL_AEGIS_KEY = bytes.fromhex("16cfd6720ab4cddcb992d16798978c5e5fab4ee71e06be1172d2bcc4e83b8b99")
OVERKILL_AEGIS_KEY = bytes.fromhex("4db461711aa9d9a1808c129e5d88485750c226c5b47231c1f4ad83588fac71d4")
OVERKILL_XCHACHA_KEY = bytes.fromhex("3dc0d8c58c1e4ed786858c617f36831a1e5700e964af745ee2bdaf08624edc9d")

NORMAL_AEGIS_NONCE = bytes.fromhex("8c25bb161126592c0ac384541c4655277f94b71bcbd4961e322f674678501fbd")
OVERKILL_AEGIS_NONCE = bytes.fromhex("d35b030c479fa165ca86676d2b81f8903cf04dcc744e51c15704059a1e252b57")
OVERKILL_XCHACHA_NONCE = bytes.fromhex("6b5fdb6d5fd18cdcfb98b24fa3bbd9da076d9d9ab8a42e28")


def test_derive_master():
    norm_obj = KDF(salt=SALT, mode=Header.NORMAL, password=PASSWORD)
    over_obj = KDF(salt=SALT, mode=Header.OVERKILL, password=PASSWORD)
    assert kdf.derive_master(norm_obj) == NORMAL_MASTER_KEY
    assert kdf.derive_master(over_obj) == OVERKILL_MASTER_KEY


def test_derive_aegis_key():
    assert kdf.derive_aegis_key(NORMAL_MASTER_KEY) == NORMAL_AEGIS_KEY
    assert kdf.derive_aegis_key(OVERKILL_MASTER_KEY) == OVERKILL_AEGIS_KEY


def test_derive_xchacha_key():
    assert kdf.derive_xchacha_key(OVERKILL_MASTER_KEY) == OVERKILL_XCHACHA_KEY


def test_derive_aegis_nonce():
    assert kdf.derive_aegis_nonce(NORMAL_MASTER_KEY) == NORMAL_AEGIS_NONCE
    assert kdf.derive_aegis_nonce(OVERKILL_MASTER_KEY) == OVERKILL_AEGIS_NONCE


def test_derive_xchacha_nonce():
    assert kdf.derive_xchacha_nonce(OVERKILL_MASTER_KEY) == OVERKILL_XCHACHA_NONCE
