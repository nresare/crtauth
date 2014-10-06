import unittest
import sys
from crtauth import msgpack_protocol, exceptions

SERIALIZED = (
    '\x01c\xc4\x14uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2'
    '\xceQ]\x88\xae\xceQ]\x89\xda\xc4\x06L\x9a\x07\x12\xcb\x1e\xb2ser'
    'ver.example.com\xa8username'
)


class MsgpackTest(unittest.TestCase):
    def test_build_token(self):
        challenge = msgpack_protocol.Challenge(
            unique_data='uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2',
            valid_from=1365084334,
            valid_to=1365084634,
            fingerprint='L\x9a\x07\x12\xcb\x1e',
            server_name='server.example.com',
            username='username'
        )

        self.assertEqual(challenge.serialize(), SERIALIZED)

        another = msgpack_protocol.Challenge.deserialize(SERIALIZED)
        for field in ("unique_data", "valid_from", "valid_to", "fingerprint",
                      "server_name", "username"):
            self.assertEquals(getattr(another, field), getattr(challenge,
                                                               field))

    def test_wrong_type_unique_data(self):
        challenge = msgpack_protocol.Challenge(
            unique_data=42,
            valid_from=1365084334,
            valid_to=1365084634,
            fingerprint='L\x9a\x07\x12\xcb\x1e',
            server_name='server.example.com',
            username='username'
        )
        self.assertRaises(ValueError, challenge.serialize)

    def test_wrong_number_of_parameters(self):
        self.assertRaises(RuntimeError, msgpack_protocol.Challenge)

    def test_wrong_name_parameters(self):
        self.assertRaises(RuntimeError, msgpack_protocol.Challenge, a=1, b=2,
                          c=3, d=4, e=5, f=6)

    def test_serialize_no_classes_magic(self):
        class Dummy(msgpack_protocol.MessageBase):
            def __init__(self):
                self.__fields__ = ()
        self.assertRaises(RuntimeError, Dummy().serialize)

    def test_wrong_version(self):
        with self.assertRaises(exceptions.ProtocolError) as e:
            msgpack_protocol.Challenge.deserialize("foo")
        self._starts_with(e.exception.message, "Wrong version")

    def test_wrong_magic(self):
        with self.assertRaises(exceptions.ProtocolError) as e:
            msgpack_protocol.Challenge.deserialize("\x01f")
        self._starts_with(e.exception.message, "Wrong magic")

    def test_add_hmac(self):
        challenge = msgpack_protocol.Challenge(
            unique_data='uXFO\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2',
            valid_from=1365084334,
            valid_to=1365084634,
            fingerprint='L\x9a\x07\x12\xcb\x1e',
            server_name='server.example.com',
            username='username'
        )
        s = challenge.serialize(hmac_secret='gurkburk')
        self.assertEquals(
            s, SERIALIZED + "\xda\x00 CaXJ\xd8\xf2\xca\xad\xdebQ5\x18\x10c"
            "{\xf1]\x1aC\x7ff\x86\xb54\x95\x12\xd0\x96\x17\x9a\xbe")


    def _starts_with(self, message, prefix):
        if not message.startswith(prefix):
            self.assertFalse("Expected '%s' to be prefix of '%s"
                             % (prefix, message))



