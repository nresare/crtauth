# Copyright (c) 2011-2013 Spotify AB
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
from io import BytesIO
import io
import msgpack
from crtauth import exceptions

PROTOCOL_VERSION = 1


class TypeInfo(object):
    def __init__(self, data_type, size=None, binary=False):
        self._data_type = data_type
        self._size = size
        self._packer = msgpack.Packer(use_bin_type=binary)

    def validate(self, data):
        if not isinstance(data, self._data_type):
            raise ValueError("Value should have been of type str")

    def pack(self, value, stream):
        stream.write(self._packer.pack(value))


class MessageBase(object):
    __fields__ = None
    __magic__ = None

    def __init__(self, **kw):
        if len(kw) != len(self.__fields__):
            raise Exception("Wrong number of constructor parameters")

        for key, _ in self.__fields__:
            val = kw.get(key, None)
            if val is None:
                raise RuntimeError(
                    "Missing required argument '%s'" % key)
            setattr(self, key, val)

    def serialize(self, hmac_secret=None):
        if self.__magic__ is None or self.__fields__ is None:
            raise RuntimeError(
                "Serialization can only be performed on classes implementing "
                "__fields__ and __magic__")
        buf = io.BytesIO()
        msgpack.pack(PROTOCOL_VERSION, buf)
        msgpack.pack(self.__magic__, buf)
        for name, type_info in self.__fields__:
            value = getattr(self, name)
            type_info.validate(value)
            type_info.pack(value, buf)
        return buf.getvalue()

    @classmethod
    def deserialize(cls, serialized):
        stream = io.BytesIO(serialized)
        unpacker = msgpack.Unpacker(stream)
        version = unpacker.unpack()
        if version != PROTOCOL_VERSION:
            raise exceptions.ProtocolException(
                "Wrong version, expected %d got %d" % (PROTOCOL_VERSION, version))
        magic = unpacker.unpack()
        if magic != cls.__magic__:
            raise exceptions.ProtocolException(
                "Wrong magic, expected %d got %d" % (cls.__magic__, magic))
        kw = dict()
        for name, type_info in cls.__fields__:
            kw[name] = unpacker.unpack()
        return cls(**kw)


class Challenge(MessageBase):
    """
    A challenge.
    """
    __magic__ = ord('c')
    __fields__ = (
        ("unique_data", TypeInfo(str, 20, binary=True)),
        ("valid_from", TypeInfo(int)),
        ("valid_to", TypeInfo(int)),
        ("fingerprint", TypeInfo(str, 6, binary=True)),
        ("server_name", TypeInfo(str)),
        ("username", TypeInfo(str))
    )
