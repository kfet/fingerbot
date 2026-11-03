"""Pure-Python AES-128 against the published vectors, and against pycryptodome."""
from __future__ import annotations

import os

import pytest

import fingerbot

H = bytes.fromhex


def test_sbox_known_entries():
    # FIPS-197 figure 7 / figure 14 spot checks
    assert fingerbot._SBOX[0x00] == 0x63
    assert fingerbot._SBOX[0x53] == 0xED
    assert fingerbot._SBOX[0xFF] == 0x16
    assert fingerbot._INV_SBOX[0x63] == 0x00
    assert sorted(fingerbot._SBOX) == list(range(256))


def test_key_expansion_fips197_a1():
    rk = fingerbot._expand_key(H("2b7e151628aed2a6abf7158809cf4f3c"))
    assert bytes(rk[1]) == H("a0fafe1788542cb123a339392a6c7605")
    assert bytes(rk[10]) == H("d014f9a8c9ee2589e13f0cc8b6630ca6")


@pytest.mark.parametrize(("key", "pt", "ct"), [
    # FIPS-197 appendix B
    ("2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
     "3925841d02dc09fbdc118597196a0b32"),
    # FIPS-197 appendix C.1
    ("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
])
def test_block_fips197(key, pt, ct):
    rk = fingerbot._expand_key(H(key))
    assert fingerbot._encrypt_block(rk, H(pt)) == H(ct)
    assert fingerbot._decrypt_block(rk, H(ct)) == H(pt)


SP800_38A_KEY = H("2b7e151628aed2a6abf7158809cf4f3c")
SP800_38A_IV = H("000102030405060708090a0b0c0d0e0f")
SP800_38A_PT = H("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
                 "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
SP800_38A_CT = H("7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
                 "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7")


def test_cbc_sp800_38a_f21():
    assert fingerbot.aes_cbc_encrypt(SP800_38A_KEY, SP800_38A_IV, SP800_38A_PT) == SP800_38A_CT
    assert fingerbot.aes_cbc_decrypt(SP800_38A_KEY, SP800_38A_IV, SP800_38A_CT) == SP800_38A_PT


def test_cbc_empty_is_empty():
    assert fingerbot.aes_cbc_encrypt(SP800_38A_KEY, SP800_38A_IV, b"") == b""


@pytest.mark.parametrize(("key", "iv", "data", "match"), [
    (b"short", bytes(16), bytes(16), "key must be 16"),
    (bytes(16), b"short", bytes(16), "IV must be 16"),
    (bytes(16), bytes(16), bytes(15), "multiple of 16"),
])
def test_cbc_rejects_bad_sizes(key, iv, data, match):
    with pytest.raises(ValueError, match=match):
        fingerbot.aes_cbc_encrypt(key, iv, data)
    with pytest.raises(ValueError, match=match):
        fingerbot.aes_cbc_decrypt(key, iv, data)


def test_cbc_matches_pycryptodome_random():
    aes = pytest.importorskip("Crypto.Cipher.AES")
    for n in range(40):
        key, iv = os.urandom(16), os.urandom(16)
        data = os.urandom(16 * (n % 6))
        ref = aes.new(key, aes.MODE_CBC, iv).encrypt(data)
        assert fingerbot.aes_cbc_encrypt(key, iv, data) == ref
        assert fingerbot.aes_cbc_decrypt(key, iv, ref) == data
