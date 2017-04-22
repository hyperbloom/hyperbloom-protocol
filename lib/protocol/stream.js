'use strict';

const assert = require('assert');
const util = require('util');
const sodium = require('sodium-universal');
const signatures = require('sodium-signatures');
const varint = require('varint');
const constants = require('hyperbloom-constants');
const HyperBloomChain = require('hyperbloom-chain');
const OffsetBuffer = require('obuf');

const protocol = require('../protocol');
const messages = protocol.messages;

const Buffer = require('buffer').Buffer;
const Duplex = require('stream').Duplex;

const MAGIC = Buffer.from('d572c875', 'hex');

const PUBLIC_KEY_SIZE = constants.PUBLIC_KEY_SIZE;
const PRIVATE_KEY_SIZE = constants.PRIVATE_KEY_SIZE;
const ID_SIZE = 32;

// This is enough to transfer bloom filter with about 64k entries
const MAX_PENDING_SIZE = 256 * 1024;

const DISCOVERY_HASH_KEY = constants.DISCOVERY_HASH_KEY;
const DISCOVERY_KEY_SIZE = constants.DISCOVERY_KEY_SIZE;

const HASH_KEY = constants.HASH_KEY;
const HASH_SIZE = constants.HASH_SIZE;
const EMPTY_HASH = Buffer.alloc(HASH_SIZE);

// X-Salsa 20 uses 192-bit nonce
const NONCE_SIZE = 24;

function Stream(options) {
  Duplex.call(this);

  // Validation
  this.options = options || {};
  assert(Buffer.isBuffer(this.options.feedKey),
         'options.feedKey must be a Buffer');
  assert.equal(this.options.feedKey.length, PUBLIC_KEY_SIZE,
               `options.feedKey must have size ${PUBLIC_KEY_SIZE}`);
  assert(Buffer.isBuffer(this.options.privateKey),
         'options.privateKey must be a Buffer');
  assert.equal(this.options.privateKey.length, PRIVATE_KEY_SIZE,
               `options.privateKey must have size ${PRIVATE_KEY_SIZE}`);

  assert(Array.isArray(this.options.chain), 'options.chain must be an Array');
  assert(this.options.chain.length <= constants.MAX_CHAIN_LENGTH,
         `Maximum chain length size is ${constants.MAX_CHAIN_LENGTH}`);

  this.feedKey = this.options.feedKey;
  this.feed = this.options.discoveryKey || this._discoveryKey(this.feedKey);
  assert.equal(this.feed.length, DISCOVERY_KEY_SIZE,
               `options.discoverKey must have size ${DISCOVERY_KEY_SIZE}`);

  // Init
  this.privateKey = this.options.privateKey;

  this.chain = new HyperBloomChain({ root: this.feedKey });

  // Verify chain early
  {
    const sign = signatures.sign(EMPTY_HASH, this.privateKey);
    this.chain.verify(this.options.chain, EMPTY_HASH, sign);
  }

  this.id = this._randomBytes(ID_SIZE);

  this.secure = false;

  // Needed to verify the handshake
  this._nonceHash = null;

  // Encryption state
  this._xor = {
    self: null,
    remote: null
  };
  this._remote = {
    id: null,
    chain: null
  };

  this._pending = new OffsetBuffer();
  this._state = 'magic';
  this._waiting = MAGIC.length;
  this._varint = { value: 0, shift: 0 };

  // Queue of messages to be sent on `secure`
  this._queue = [];

  this._open();
}
util.inherits(Stream, Duplex);
module.exports = Stream;

Stream.prototype._write = function _write(data, enc, cb) {
  if (this._xor.remote !== null)
    this._xor.remote.update(data, data);
  this._pending.push(data);

  while (this._pending.size >= this._waiting) {
    try {
      if (!this._parse())
        break;
    } catch (e) {
      return cb(e);
    }
  }

  if (this._pending.size >= MAX_PENDING_SIZE)
    return cb(new Error('Message is too big'));

  cb(null);
};

Stream.prototype._read = function _read(bytes) {
  // no-op, we `.push()`
};

Stream.prototype._randomBytes = function _randomBytes(size) {
  const res = Buffer.alloc(size);
  sodium.randombytes_buf(res);
  return res;
};

Stream.prototype._discoveryKey = function _discoveryKey(feedKey) {
  const out = Buffer.alloc(DISCOVERY_KEY_SIZE);
  // See: https://github.com/mafintosh/hypercore/issues/93
  // Quirky, but safe
  sodium.crypto_generichash(out, DISCOVERY_HASH_KEY, feedKey);
  return out;
};

Stream.prototype._hash = function _hash(input) {
  const out = Buffer.alloc(HASH_SIZE);
  sodium.crypto_generichash(out, input, HASH_KEY);
  return out;
};

Stream.prototype._parse = function _parse() {
  if (this._state === 'magic')
    return this._parseMagic();
  else if (this._state === 'open:length' || this._state === 'msg:length')
    return this._parseLength();
  else if (this._state === 'open:body')
    return this._parseOpen();

  // msg:body
  const msg = this._pending.take(this._waiting);
  this._waiting = 1;
  this._state = 'msg:length';

  let offset = 0;

  const id = varint.decode(msg, offset);
  offset += varint.decode.bytes;

  let type;
  let Type;
  if (id === messages.id.HANDSHAKE) {
    type = 'handshake';
    Type = messages.Handshake;
  } else if (id === messages.id.SYNC) {
    type = 'sync';
    Type = messages.Sync;
  } else if (id === messages.id.FILTER_OPTIONS) {
    type = 'filter-options';
    Type = messages.FilterOptions;
  } else if (id === messages.id.DATA) {
    type = 'data';
    Type = messages.Data;
  } else if (id === messages.id.REQUEST) {
    type = 'request';
    Type = messages.Request;
  } else {
    // Unknown message, ignore
    return true;
  }

  const body = Type.decode(msg, offset, msg.length);
  if (type === 'handshake')
    this._onHandshake(body);
  else
    this.emit('message', { type, body });

  return true;
};

Stream.prototype._parseMagic = function _parseMagic() {
  const actual = this._pending.take(MAGIC.length);
  if (!actual.equals(MAGIC))
    throw new Error('Invalid MAGIC value');

  this._waiting = 1;
  this._state = 'open:length';
  return true;
};

Stream.prototype._parseLength = function _parseLength() {
  while (this._pending.size !== 0) {
    const b = this._pending.readUInt8();
    const msb = b & 0x80;
    const rest = b & 0x7f;

    this._varint.value |= rest << this._varint.shift;
    this._varint.shift += 7;
    if (this._varint.shift >= 25)
      throw new Error('varint doesn\'t fit into 32-bit value');

    if (!msb) {
      this._state = this._state === 'open:length' ? 'open:body' : 'msg:body';

      this._waiting = this._varint.value >>> 0;
      if (this._waiting > MAX_PENDING_SIZE)
        throw new Error('Message length is too big');

      this._varint.value = 0;
      this._varint.shift = 0;
      return true;
    }
  }

  return false;
};

Stream.prototype._parseOpen = function _parseOpen() {
  const raw = this._pending.take(this._waiting);

  this._waiting = 1;
  this._state = 'msg:length';

  const open = messages.Open.decode(raw);
  if (!open.feed.equals(this.feed))
    throw new Error('Feed mismatch');
  if (open.nonce.length !== NONCE_SIZE)
    throw new Error('Invalid nonce size');

  this._xor.remote = sodium.crypto_stream_xor_instance(open.nonce,
                                                       this.feedKey);
  this._handshake(open.nonce);

  // Decrypt pending data
  const pending = this._pending.take(this._pending.size);
  this._xor.remote.update(pending, pending);
  this._pending.push(pending);

  return true;
};

Stream.prototype._open = function _open() {
  const nonce = this._randomBytes(NONCE_SIZE);
  this._nonceHash = this._hash(nonce);

  const msg = {
    feed: this.feed,
    nonce
  };
  const msgLen = messages.Open.encodingLength(msg);
  const buf = Buffer.alloc(MAGIC.length +
                           varint.encodingLength(msgLen) +
                           msgLen);

  let offset = MAGIC.copy(buf, 0);
  varint.encode(msgLen, buf, offset);
  offset += varint.encode.bytes;
  messages.Open.encode(msg, buf, offset);
  this.push(buf);

  this._xor.self = sodium.crypto_stream_xor_instance(nonce, this.feedKey);
};

Stream.prototype._send = function _send(id, Type, content) {
  const idLen = varint.encodingLength(id);
  const msgLen = Type.encodingLength(content);

  const buf = Buffer.alloc(varint.encodingLength(idLen + msgLen) +
                           idLen +
                           msgLen);

  let offset = 0;
  varint.encode(idLen + msgLen, buf, offset);
  offset += varint.encode.bytes;

  varint.encode(id, buf, offset);
  offset += varint.encode.bytes;

  Type.encode(content, buf, offset);

  this._xor.self.update(buf, buf);
  this.push(buf);
};

Stream.prototype._handshake = function _handshake(remoteNonce) {
  this._send(messages.id.HANDSHAKE, messages.Handshake, {
    id: this.id,
    chain: this.options.chain,
    signature: signatures.sign(this._hash(remoteNonce), this.privateKey)
  });
};

Stream.prototype._verifyChain = function _verifyChain(chain, signature) {
  if (chain.length !== 0)
    throw new Error('Sorry, not supported yet');

  const pub = this.feedKey;
  const verified = signatures.verify(this._nonceHash, signature, pub);
  if (!verified)
    throw new Error('Failed to verify the handshake signature');
};

Stream.prototype._onHandshake = function _onHandshake(body) {
  this.chain.verify(body.chain, this._nonceHash, body.signature);

  this._remote.id = body.id;
  this._remote.chain = body.chain;

  this.secure = true;
  this.emit('secure', { id: body.id, chain: body.chain });

  const queue = this._queue;
  this._queue = null;
  queue.forEach(cb => cb());
};

// Public API

Stream.prototype._secureSend = function _secureSend(id, Type, content) {
  // Just to validate that all required fields are present
  Type.encodingLength(content);

  if (!this.secure) {
    this._queue.push(() => this._secureSend(id, Type, content));
    return;
  }

  this._send(id, Type,  content);
};

Stream.prototype.sync = function sync(body) {
  this._secureSend(messages.id.SYNC, messages.Sync, body);
};

Stream.prototype.filterOptions = function filterOptions(body) {
  this._secureSend(messages.id.FILTER_OPTIONS, messages.FilterOptions, body);
};

Stream.prototype.data = function data(body) {
  this._secureSend(messages.id.DATA, messages.Data, body);
};

Stream.prototype.request = function request(body) {
  this._secureSend(messages.id.REQUEST, messages.Request, body);
};
