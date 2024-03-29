# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: wedgeblock.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='wedgeblock.proto',
  package='wedgeblock',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x10wedgeblock.proto\x12\nwedgeblock\"?\n\x0bTransaction\x12\x1d\n\x02rw\x18\x01 \x01(\x0b\x32\x11.wedgeblock.RWSet\x12\x11\n\tsignature\x18\x02 \x01(\x0c\"D\n\x05RWSet\x12!\n\x04type\x18\x01 \x01(\x0e\x32\x13.wedgeblock.TxnType\x12\x0b\n\x03key\x18\x02 \x01(\x0c\x12\x0b\n\x03val\x18\x03 \x01(\x0c\"a\n\x05Hash1\x12\x10\n\x08logIndex\x18\x01 \x01(\x05\x12\x1d\n\x02rw\x18\x02 \x01(\x0b\x32\x11.wedgeblock.RWSet\x12\x12\n\nmerkleRoot\x18\x03 \x01(\t\x12\x13\n\x0bmerkleProof\x18\x04 \x01(\x0c\"A\n\rHash1Response\x12\x1d\n\x02h1\x18\x01 \x01(\x0b\x32\x11.wedgeblock.Hash1\x12\x11\n\tsignature\x18\x02 \x01(\x0c\"/\n\x07LogHash\x12\x10\n\x08logIndex\x18\x01 \x01(\x05\x12\x12\n\nmerkleRoot\x18\x02 \x01(\t\"A\n\x05Hash2\x12\x0f\n\x07TxnHash\x18\x01 \x01(\x0c\x12\'\n\x06status\x18\x02 \x01(\x0e\x32\x17.wedgeblock.Hash2Status\"-\n\x08LogEntry\x12\r\n\x05index\x18\x01 \x01(\x05\x12\x12\n\nmerkleTree\x18\x02 \x01(\x0c\"\x19\n\x08LogIndex\x12\r\n\x05index\x18\x01 \x01(\x05*\x19\n\x07TxnType\x12\x06\n\x02RO\x10\x00\x12\x06\n\x02RW\x10\x01*4\n\x0bHash2Status\x12\x0b\n\x07INVALID\x10\x00\x12\r\n\tNOT_READY\x10\x01\x12\t\n\x05VALID\x10\x02\x32\x82\x01\n\x08\x45\x64geNode\x12=\n\x07\x45xecute\x12\x17.wedgeblock.Transaction\x1a\x19.wedgeblock.Hash1Response\x12\x37\n\rGetPhase2Hash\x12\x13.wedgeblock.LogHash\x1a\x11.wedgeblock.Hash2b\x06proto3'
)

_TXNTYPE = _descriptor.EnumDescriptor(
  name='TxnType',
  full_name='wedgeblock.TxnType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='RO', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RW', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=523,
  serialized_end=548,
)
_sym_db.RegisterEnumDescriptor(_TXNTYPE)

TxnType = enum_type_wrapper.EnumTypeWrapper(_TXNTYPE)
_HASH2STATUS = _descriptor.EnumDescriptor(
  name='Hash2Status',
  full_name='wedgeblock.Hash2Status',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='INVALID', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='NOT_READY', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='VALID', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=550,
  serialized_end=602,
)
_sym_db.RegisterEnumDescriptor(_HASH2STATUS)

Hash2Status = enum_type_wrapper.EnumTypeWrapper(_HASH2STATUS)
RO = 0
RW = 1
INVALID = 0
NOT_READY = 1
VALID = 2



_TRANSACTION = _descriptor.Descriptor(
  name='Transaction',
  full_name='wedgeblock.Transaction',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='rw', full_name='wedgeblock.Transaction.rw', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signature', full_name='wedgeblock.Transaction.signature', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=32,
  serialized_end=95,
)


_RWSET = _descriptor.Descriptor(
  name='RWSet',
  full_name='wedgeblock.RWSet',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='type', full_name='wedgeblock.RWSet.type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='key', full_name='wedgeblock.RWSet.key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='val', full_name='wedgeblock.RWSet.val', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=97,
  serialized_end=165,
)


_HASH1 = _descriptor.Descriptor(
  name='Hash1',
  full_name='wedgeblock.Hash1',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='logIndex', full_name='wedgeblock.Hash1.logIndex', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='rw', full_name='wedgeblock.Hash1.rw', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='merkleRoot', full_name='wedgeblock.Hash1.merkleRoot', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='merkleProof', full_name='wedgeblock.Hash1.merkleProof', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=167,
  serialized_end=264,
)


_HASH1RESPONSE = _descriptor.Descriptor(
  name='Hash1Response',
  full_name='wedgeblock.Hash1Response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='h1', full_name='wedgeblock.Hash1Response.h1', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signature', full_name='wedgeblock.Hash1Response.signature', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=266,
  serialized_end=331,
)


_LOGHASH = _descriptor.Descriptor(
  name='LogHash',
  full_name='wedgeblock.LogHash',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='logIndex', full_name='wedgeblock.LogHash.logIndex', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='merkleRoot', full_name='wedgeblock.LogHash.merkleRoot', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=333,
  serialized_end=380,
)


_HASH2 = _descriptor.Descriptor(
  name='Hash2',
  full_name='wedgeblock.Hash2',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='TxnHash', full_name='wedgeblock.Hash2.TxnHash', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='status', full_name='wedgeblock.Hash2.status', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=382,
  serialized_end=447,
)


_LOGENTRY = _descriptor.Descriptor(
  name='LogEntry',
  full_name='wedgeblock.LogEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='index', full_name='wedgeblock.LogEntry.index', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='merkleTree', full_name='wedgeblock.LogEntry.merkleTree', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=449,
  serialized_end=494,
)


_LOGINDEX = _descriptor.Descriptor(
  name='LogIndex',
  full_name='wedgeblock.LogIndex',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='index', full_name='wedgeblock.LogIndex.index', index=0,
      number=1, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=496,
  serialized_end=521,
)

_TRANSACTION.fields_by_name['rw'].message_type = _RWSET
_RWSET.fields_by_name['type'].enum_type = _TXNTYPE
_HASH1.fields_by_name['rw'].message_type = _RWSET
_HASH1RESPONSE.fields_by_name['h1'].message_type = _HASH1
_HASH2.fields_by_name['status'].enum_type = _HASH2STATUS
DESCRIPTOR.message_types_by_name['Transaction'] = _TRANSACTION
DESCRIPTOR.message_types_by_name['RWSet'] = _RWSET
DESCRIPTOR.message_types_by_name['Hash1'] = _HASH1
DESCRIPTOR.message_types_by_name['Hash1Response'] = _HASH1RESPONSE
DESCRIPTOR.message_types_by_name['LogHash'] = _LOGHASH
DESCRIPTOR.message_types_by_name['Hash2'] = _HASH2
DESCRIPTOR.message_types_by_name['LogEntry'] = _LOGENTRY
DESCRIPTOR.message_types_by_name['LogIndex'] = _LOGINDEX
DESCRIPTOR.enum_types_by_name['TxnType'] = _TXNTYPE
DESCRIPTOR.enum_types_by_name['Hash2Status'] = _HASH2STATUS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Transaction = _reflection.GeneratedProtocolMessageType('Transaction', (_message.Message,), {
  'DESCRIPTOR' : _TRANSACTION,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.Transaction)
  })
_sym_db.RegisterMessage(Transaction)

RWSet = _reflection.GeneratedProtocolMessageType('RWSet', (_message.Message,), {
  'DESCRIPTOR' : _RWSET,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.RWSet)
  })
_sym_db.RegisterMessage(RWSet)

Hash1 = _reflection.GeneratedProtocolMessageType('Hash1', (_message.Message,), {
  'DESCRIPTOR' : _HASH1,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.Hash1)
  })
_sym_db.RegisterMessage(Hash1)

Hash1Response = _reflection.GeneratedProtocolMessageType('Hash1Response', (_message.Message,), {
  'DESCRIPTOR' : _HASH1RESPONSE,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.Hash1Response)
  })
_sym_db.RegisterMessage(Hash1Response)

LogHash = _reflection.GeneratedProtocolMessageType('LogHash', (_message.Message,), {
  'DESCRIPTOR' : _LOGHASH,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.LogHash)
  })
_sym_db.RegisterMessage(LogHash)

Hash2 = _reflection.GeneratedProtocolMessageType('Hash2', (_message.Message,), {
  'DESCRIPTOR' : _HASH2,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.Hash2)
  })
_sym_db.RegisterMessage(Hash2)

LogEntry = _reflection.GeneratedProtocolMessageType('LogEntry', (_message.Message,), {
  'DESCRIPTOR' : _LOGENTRY,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.LogEntry)
  })
_sym_db.RegisterMessage(LogEntry)

LogIndex = _reflection.GeneratedProtocolMessageType('LogIndex', (_message.Message,), {
  'DESCRIPTOR' : _LOGINDEX,
  '__module__' : 'wedgeblock_pb2'
  # @@protoc_insertion_point(class_scope:wedgeblock.LogIndex)
  })
_sym_db.RegisterMessage(LogIndex)



_EDGENODE = _descriptor.ServiceDescriptor(
  name='EdgeNode',
  full_name='wedgeblock.EdgeNode',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=605,
  serialized_end=735,
  methods=[
  _descriptor.MethodDescriptor(
    name='Execute',
    full_name='wedgeblock.EdgeNode.Execute',
    index=0,
    containing_service=None,
    input_type=_TRANSACTION,
    output_type=_HASH1RESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='GetPhase2Hash',
    full_name='wedgeblock.EdgeNode.GetPhase2Hash',
    index=1,
    containing_service=None,
    input_type=_LOGHASH,
    output_type=_HASH2,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_EDGENODE)

DESCRIPTOR.services_by_name['EdgeNode'] = _EDGENODE

# @@protoc_insertion_point(module_scope)
