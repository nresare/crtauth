# Copyright (c) 2011-2014 Spotify AB
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import with_statement

import hashlib
import hmac
import time

from crtauth import ssh
from crtauth import exceptions
from crtauth import protocol
from crtauth import msgpack_protocol

# The maximum number of seconds from a challenge is created to the time when
# the generated response is processed. This needs to compensate for clock
# skew between servers in a cluster.
RESP_TIMEOUT = 20

# The number of seconds a clock can be off before we start getting too
# old / too new messages
CLOCK_FUDGE = 2


class AuthServer(object):
    def __init__(self, secret, key_provider, server_name, token_lifetime=60,
                 now_func=time.time, legacy_support=True):
        """
        Constructs a new AuthServer object, with the given parameters.

        @param secret a string containing the secret data used to authenticate
        requests

        @param key_provider a subclass of KeyProvider

        @param server_name a text string included in the challenge that needs
        to match the host that the client connects to

        @param token_lifetime the number of seconds that a token issued by
        this instance should be valid for

        @param now_func a function that returns current time in unix seconds.
        Used for testing
        """

        self.token_lifetime = token_lifetime
        self.secret = secret
        self.key_provider = key_provider
        self.urandom = open("/dev/urandom", "r")
        self.server_name = server_name
        self.now_func = now_func
        self.legacy_support = legacy_support

    def create_challenge(self, username, version=0):
        """This method returns a challenge suitable for ssh-agent signing.

        :param username: the username of the user requesting a challenge
        :param version: the highest protocol version the clients supports
        :exception ProtocolVersionError if the client supports
        """
        key = self.key_provider.get_key(username)

        if version < 1:
            if not self.legacy_support:
                raise exceptions.ProtocolVersionError(
                    "Client needs to support at least version 1")

            c = protocol.Challenge(fingerprint=key.fingerprint(),
                                   server_name=self.server_name,
                                   unique_data=self.urandom.read(20),
                                   valid_from=int(self.now_func() - CLOCK_FUDGE),
                                   valid_to=int(self.now_func() + RESP_TIMEOUT),
                                   username=username)
            b = c.serialize()

            payload = protocol.VerifiablePayload(digest=self._hmac(b), payload=b)
            return ssh.base64url_encode(payload.serialize())
        else:
            c = msgpack_protocol.Challenge(
                fingerprint=key.fingerprint(),
                server_name=self.server_name,
                unique_data=self.urandom.read(20),
                valid_from=int(self.now_func() - CLOCK_FUDGE),
                valid_to=int(self.now_func() + RESP_TIMEOUT),
                username=username)
            return ssh.base64url_encode(c.serialize(self.secret))

    def create_token(self, response):
        """
        This method verifies that the response given from the client
        is valid and if so returns a token used for authentication.
        """
        s = ssh.base64url_decode(response)

        if s[0] == 'r':
            # this is a version 0 response
            version_1 = False
            if not self.legacy_support:
                raise exceptions.ProtocolVersionError(
                    "Client needs to support at least version 1")
            r = protocol.Response.deserialize(s)
            if not r.hmac_challenge.verify(self._hmac):
                raise exceptions.InvalidInputException(
                    "Challenge hmac verification failed, not matching  secret"
                )
            challenge = protocol.Challenge.deserialize(r.hmac_challenge.payload)
        elif s[0] == '\x01':
            # this is a version 1 response
            version_1 = True
            r = msgpack_protocol.Response.deserialize(s)
            challenge = msgpack_protocol.Challenge.deserialize_authenticated(
                r.challenge, self.secret)
        else:
            raise exceptions.ProtocolError("invalid first byte of response")

        # verify the integrity of the challenge in the response
        if self.server_name != challenge.server_name:
            s = "Got challenge with the wrong server_name encoded"
            raise exceptions.InvalidInputException(s)

        key = self.key_provider.get_key(challenge.username)

        if version_1:
            if not key.verify_signature(r.signature, r.challenge):
                raise exceptions.InvalidInputException(
                    "Client did not provide proof that it controls "
                    "the secret key")
        else:
            if not key.verify_signature(r.signature, r.hmac_challenge.payload):
                raise exceptions.InvalidInputException(
                    "Client did not provide proof that it controls "
                    "the secret key")

        if challenge.valid_from > self.now_func():
            s = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                              time.gmtime(challenge.valid_from))
            raise exceptions.InvalidInputException("Response with challenge "
                                                   "created as %s too new "
                                                   % s)

        if challenge.valid_to < self.now_func():
            s = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                              time.gmtime(challenge.valid_from))
            raise exceptions.InvalidInputException("Response with challenge "
                                                   "created as %s too old "
                                                   % s)

        expire_time = int(self.now_func()) + self.token_lifetime

        return self._make_token(challenge.username, expire_time)

    def validate_token(self, token):
        buf = ssh.base64url_decode(token)
        hmac_token = protocol.VerifiablePayload.deserialize(buf)

        if not hmac_token.verify(self._hmac):
            raise exceptions.InvalidInputException("Token hmac verification "
                                                   "failed, not matching our "
                                                   "secret")

        t = protocol.Token.deserialize(hmac_token.payload)

        if t.valid_to < self.now_func():
            s = "Token expired at " + time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                                    time.gmtime(t.valid_to))
            raise exceptions.TokenExpiredException(s)

        if t.valid_from > self.now_func():
            s = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                              time.gmtime(t.valid_from))
            raise exceptions.TokenExpiredException("Token created at %s" % s)

        return t.username

    def _hmac(self, data):
        return hmac.new(self.secret, data, hashlib.sha1).digest()

    def _make_token(self, username, expire_time):
        t = protocol.Token(username=username,
                           valid_from=int(self.now_func() - CLOCK_FUDGE),
                           valid_to=expire_time)

        b = t.serialize()

        payload = protocol.VerifiablePayload(digest=self._hmac(b), payload=b)

        return ssh.base64url_encode(payload.serialize())


def create_response(challenge, server_name, signer_plug=None):
    """Called by a client with the challenge provided by the server
    to generate a response using the local ssh-agent"""

    b = ssh.base64url_decode(challenge)


    if b[0] == 'v':
        # this is version 0 challenge
        hmac_challenge = protocol.VerifiablePayload.deserialize(b)
        challenge = protocol.Challenge.deserialize(hmac_challenge.payload)
        to_sign = hmac_challenge.payload
        version_1 = False
    elif b[0] == '\x01':
        # version 1
        challenge = msgpack_protocol.Challenge.deserialize(b)
        to_sign = b
        version_1 = True
    else:
        raise exceptions.ProtocolError("invalid first byte of challenge")

    fingerprint = challenge.fingerprint
    if challenge.server_name != server_name:
        s = ("Possible MITM attack. Challenge originates from '%s' "
             "and not '%s'" % (challenge.server_name, server_name))
        raise exceptions.InvalidInputException(s)

    if not signer_plug:
        signer_plug = ssh.AgentSigner()

    signature = signer_plug.sign_challenge(to_sign, challenge.fingerprint)

    signer_plug.close()

    if version_1:
        response = msgpack_protocol.Response(challenge=b, signature=signature)
    else:
        response = protocol.Response(
            signature=signature, hmac_challenge=hmac_challenge)

    return ssh.base64url_encode(response.serialize())
