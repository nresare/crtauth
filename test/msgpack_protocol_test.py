import unittest
from crtauth import msgpack_protocol

SERIALIZED = (
    '\x01c\xc4\x14uX\xd6\xa7\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2'
    '\xceQ]\x88\xae\xceQ]\x89\xda\xc4\x06L\x9a\x07\x12\xcb\x1e\xb2ser'
    'ver.example.com\xa8username'
)

class MsgpackTest(unittest.TestCase):
    def test_build_token(self):
        challenge = msgpack_protocol.Challenge(
            unique_data='uX\xd6\xa7\xd2\xdb\x7f\xfe}\x7f\x93\x91 vh\x89G6\x1f\xc2',
            valid_from=1365084334,
            valid_to=1365084634,
            fingerprint='L\x9a\x07\x12\xcb\x1e',
            server_name='server.example.com',
            username='username'
        )

        self.assertEqual(challenge.serialize(), SERIALIZED)

        another = msgpack_protocol.Challenge.deserialize(SERIALIZED)
        for field in ("unique_data", "valid_from", "valid_to", "fingerprint", "server_name", "username"):
            self.assertEquals(getattr(another, field), getattr(challenge, field))
