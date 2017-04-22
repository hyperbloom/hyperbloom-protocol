'use strict';

const assert = require('assert');
const util = require('util');
const sodium = require('sodium-universal');
const varint = require('varint');
const OffsetBuffer = require('obuf');

const protocol = require('../protocol');
const messages = protocol.messages;

const Buffer = require('buffer').Buffer;
const Duplex = require('stream').Duplex;

const MAGIC = Buffer.from('d572c875', 'hex');

const PUBLIC_KEY_SIZE = 32;
const ID_SIZE = 32;

// This is enough to transfer bloom filter with about 64k entries
const MAX_PENDING_SIZE = 256 * 1024;

const DISCOVERY_HASH_KEY = Buffer.from('hypercore');
const DISCOVERY_KEY_SIZE = 32;

// X-Salsa 20 uses 192-bit nonce
const NONCE_SIZE = 24;

function Stream(options) {
  Duplex.call(this);

  this.options = options || {};
  assert(Buffer.isBuffer(this.options.publicKey),
         'options.publicKey must be a Buffer');
  assert.equal(this.options.publicKey.length, PUBLIC_KEY_SIZE,
               `options.publicKey must have size ${PUBLIC_KEY_SIZE}`);

  this.publicKey = this.options.publicKey;
  this.feed = this.options.discoveryKey || this._discoveryKey(this.publicKey);
  assert.equal(this.feed.length, DISCOVERY_KEY_SIZE,
               `options.discoverKey must have size ${DISCOVERY_KEY_SIZE}`);

  this.id = this._randomBytes(ID_SIZE);

  // Encryption state
  this._xor = {
    self: null,
    other: null
  };

  this._pending = new OffsetBuffer();

  this._open();
}
util.inherits(Stream, Duplex);
module.exports = Stream;

Stream.prototype._write = function _write(data, enc, cb) {
  this._pending.push(data);

  while (this._pending.size !== 0) {
    try {
      if (!this._parseMessage())
        break;
    } catch (e) {
      return cb(e);
    }
  }

  cb();
};

Stream.prototype._read = function _read(bytes) {
  // no-op
};

Stream.prototype._randomBytes = function _randomBytes(size) {
  const res = Buffer.alloc(size);
  sodium.randombytes_buf(res);
  return res;
};

Stream.prototype._discoveryKey = function _discoveryKey(publicKey) {
  const out = Buffer.alloc(DISCOVERY_KEY_SIZE);
  sodium.crypto_generichash(out, DISCOVERY_HASH_KEY, publicKey);
  return out;
};

Stream.prototype._send = function _send(id, Type, content) {
  const idLen = varint.encodingLength(id);
  const buf = Buffer.alloc(idLen + Type.encodingLength(content));

  let offset = 0;
  varint.encode(id, buf, offset);
  offset += idLen;
  Type.encode(content, buf, offset);

  this._xor.self.update(buf, buf);
  this.push(buf);
};

Stream.prototype._parseMessage = function _parseMessage() {
  const isFirst = this._xor.other === null;

  return false;
};

Stream.prototype._open = function _open() {
  const nonce = this._randomBytes(NONCE_SIZE);

  const msg = {
    feed: this.feed,
    nonce
  };
  const buf = Buffer.alloc(MAGIC.length + messages.Open.encodingLength(msg));

  const offset = MAGIC.copy(buf, 0);
  messages.Open.encode(msg, buf, offset);
  this.push(buf);

  this._xor.self = sodium.crypto_stream_xor_instance(nonce, this.publicKey);

  this._handshake();
};

Stream.prototype._handshake = function _handshake() {
  // TODO(indutny): chain
  this._send(messages.id.HANDSHAKE, messages.Handshake, {
    id: this.id
  });
};
