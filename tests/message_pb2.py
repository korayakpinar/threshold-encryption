# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: message.proto
# Protobuf Python Version: 5.27.2
"""Generated protocol buffer code."""
from google.protobuf import message as _message
from google.protobuf import descriptor as _descriptor
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    27,
    2,
    '',
    'message.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rmessage.proto\"C\n\x11VerifyPartRequest\x12\n\n\x02pk\x18\x01 \x01(\x0c\x12\x10\n\x08gamma_g2\x18\x02 \x01(\x0c\x12\x10\n\x08part_dec\x18\x03 \x01(\x0c\"{\n\x14\x44\x65\x63ryptParamsRequest\x12\x0b\n\x03\x65nc\x18\x01 \x01(\x0c\x12\x0b\n\x03pks\x18\x02 \x03(\x0c\x12\r\n\x05parts\x18\x03 \x03(\x0c\x12\x0b\n\x03sa1\x18\x04 \x01(\x0c\x12\x0b\n\x03sa2\x18\x05 \x01(\x0c\x12\n\n\x02iv\x18\x06 \x01(\x0c\x12\t\n\x01t\x18\x07 \x01(\x04\x12\t\n\x01n\x18\x08 \x01(\x04\"@\n\x0e\x45ncryptRequest\x12\x0b\n\x03msg\x18\x01 \x01(\x0c\x12\x0b\n\x03pks\x18\x02 \x03(\x0c\x12\t\n\x01t\x18\x03 \x01(\x04\x12\t\n\x01n\x18\x04 \x01(\x04\"V\n\x0f\x45ncryptResponse\x12\x0b\n\x03\x65nc\x18\x01 \x01(\x0c\x12\x0b\n\x03sa1\x18\x02 \x01(\x0c\x12\x0b\n\x03sa2\x18\x03 \x01(\x0c\x12\n\n\x02iv\x18\x04 \x01(\x0c\x12\x10\n\x08gamma_g2\x18\x05 \x01(\x0c\"\"\n\x0eGammaG2Request\x12\x10\n\x08gamma_g2\x18\x01 \x01(\x0c\"\"\n\tPKRequest\x12\n\n\x02id\x18\x01 \x01(\x04\x12\t\n\x01n\x18\x02 \x01(\x04\"\x1a\n\x08Response\x12\x0e\n\x06result\x18\x01 \x01(\x0c\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'message_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_VERIFYPARTREQUEST']._serialized_start=17
  _globals['_VERIFYPARTREQUEST']._serialized_end=84
  _globals['_DECRYPTPARAMSREQUEST']._serialized_start=86
  _globals['_DECRYPTPARAMSREQUEST']._serialized_end=209
  _globals['_ENCRYPTREQUEST']._serialized_start=211
  _globals['_ENCRYPTREQUEST']._serialized_end=275
  _globals['_ENCRYPTRESPONSE']._serialized_start=277
  _globals['_ENCRYPTRESPONSE']._serialized_end=363
  _globals['_GAMMAG2REQUEST']._serialized_start=365
  _globals['_GAMMAG2REQUEST']._serialized_end=399
  _globals['_PKREQUEST']._serialized_start=401
  _globals['_PKREQUEST']._serialized_end=435
  _globals['_RESPONSE']._serialized_start=437
  _globals['_RESPONSE']._serialized_end=463
# @@protoc_insertion_point(module_scope)

class VerifyPartRequest(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_VERIFYPARTREQUEST']

class DecryptParamsRequest(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_DECRYPTPARAMSREQUEST']

class GammaG2Request(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_GAMMAG2REQUEST']

class GammaG2Request(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_GAMMAG2REQUEST']

class EncryptRequest(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_ENCRYPTREQUEST']

class EncryptResponse(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_ENCRYPTRESPONSE']

class PKRequest(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_PKREQUEST']

class Response(_message.Message, metaclass=_reflection.GeneratedProtocolMessageType):
  DESCRIPTOR = _globals['_RESPONSE']