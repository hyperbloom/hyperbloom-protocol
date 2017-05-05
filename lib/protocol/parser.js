'use strict';

const assert = require('assert');
const debug = require('debug')('hyperbloom:protocol');
const util = require('util');
const sodium = require('sodium-universal');
const varint = require('varint');
const constants = require('hyperbloom-constants');
const Duplex = require('stream').Duplex;
const OffsetBuffer = require('obuf');

const protocol = require('../protocol');
const messages = protocol.messages;

const Buffer = require('buffer').Buffer;

// This is enough to transfer bloom filter with about 64k entries
const MAX_PENDING_SIZE = 256 * 1024;

const HASH_KEY = constants.HASH_KEY;
const HASH_SIZE = constants.HASH_SIZE;

const MAGIC = constants.MAGIC;

// X-Salsa 20 uses 192-bit nonce
const NONCE_SIZE = 24;

let debugCounter = 0;

function Parser(id) {
  Duplex.call(this);

  this.id = id;
  if (debug.enabled)
    this._debugId = id.slice(0, 4).toString('hex') + '/' + (++debugCounter);

  // Encryption/decryption state
  this._xor = {
    self: null,
    remote: null
  };

  this._pending = new OffsetBuffer();
  this._setState('magic', MAGIC.length);
  this._varint = { value: 0, shift: 0 };
  this._gotHandshake = false;

  // `true` when we don't want new `_write()` calls
  this._paused = {
    enabled: false,
    pending: null,
    callback: null
  };
}
util.inherits(Parser, Duplex);
module.exports = Parser;

Parser.prototype._write = function _write(data, enc, cb) {
  if (this._xor.remote !== null)
    this._xor.remote.update(data, data);
  this._pending.push(data);

  this._process(cb);
};

Parser.prototype._process = function _process(cb) {
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

  if (this._paused.enabled) {
    assert(this._paused.callback === null);
    this._paused.callback = cb;
    return;
  }

  cb(null);
};

Parser.prototype._read = function _read(bytes) {
  // no-op, we `.push()`
};

Parser.prototype._randomBytes = function _randomBytes(size) {
  const res = Buffer.alloc(size);
  sodium.randombytes_buf(res);
  return res;
};

Parser.prototype._setState = function _setState(state, waiting) {
  debug('[%s] parser state=%s waiting=%d', this._debugId, state, waiting);
  this._state = state;
  this._waiting = waiting;
};

Parser.prototype._parse = function _parse() {
  if (this._state === 'magic')
    return this._parseMagic();
  else if (this._state === 'open:length' || this._state === 'msg:length')
    return this._parseLength();
  else if (this._state === 'open:body')
    return this._parseOpen();

  // msg:body
  const msg = this._pending.take(this._waiting);
  this._setState('msg:length', 1);

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
  } else if (id === messages.id.LINK) {
    type = 'link';
    Type = messages.Link;
  } else {
    // Unknown message, ignore
    return true;
  }

  if (!this._gotHandshake && type !== 'handshake')
    throw new Error('Handshake must be the first message after Open');
  if (this._gotHandshake && type === 'handshake')
    throw new Error('Handshake must be sent only once');

  debug('[%s] parser message type type=%s', this._debugId, type);

  this._gotHandshake = true;

  const body = Type.decode(msg, offset, msg.length);
  if (type === 'handshake')
    this._onHandshake(body);
  else if (type === 'link')
    this._onLink(body);
  else if (type === 'data')
    this._onData(body);
  else
    this.emit('message', { type, body });

  return true;
};

Parser.prototype._parseMagic = function _parseMagic() {
  const actual = this._pending.take(MAGIC.length);
  if (!actual.equals(MAGIC))
    throw new Error('Invalid MAGIC value');

  this._setState('open:length', 1);
  return true;
};

Parser.prototype._parseLength = function _parseLength() {
  while (this._pending.size !== 0) {
    const b = this._pending.readUInt8();
    const msb = b & 0x80;
    const rest = b & 0x7f;

    this._varint.value |= rest << this._varint.shift;
    this._varint.shift += 7;
    if (this._varint.shift >= 25)
      throw new Error('varint doesn\'t fit into 32-bit value');

    if (!msb) {
      this._setState(this._state === 'open:length' ? 'open:body' : 'msg:body',
                     this._varint.value >>> 0);

      if (this._waiting > MAX_PENDING_SIZE)
        throw new Error('Message length is too big');

      this._varint.value = 0;
      this._varint.shift = 0;
      return true;
    }
  }

  return false;
};

Parser.prototype._parseOpen = function _parseOpen() {
  const raw = this._pending.take(this._waiting);

  this._setState('paused', Infinity);

  const open = messages.Open.decode(raw);
  if (open.feed.length !== HASH_SIZE)
    throw new Error('Invalid feed size');
  if (open.nonce.length !== NONCE_SIZE)
    throw new Error('Invalid nonce size');

  assert(!this._paused.enabled);
  const pending = this._pending.take(this._pending.size);
  this._paused.pending = pending;
  this._paused.enabled = true;

  this.emit('open', open);

  return true;
};

Parser.prototype._resumeParsing = function _resumeParsing() {
  this._setState('msg:length', 1);

  this._paused.enabled = false;

  // Decrypt pending data
  const pending = this._paused.pending;
  this._paused.pending = null;
  this._xor.remote.update(pending, pending);
  this._pending.push(pending);

  let cb = this._paused.callback;
  this._paused.callback = null;
  if (!cb) {
    cb = (err) => {
      if (err)
        throw err;
    };
  }
  this._process(cb);
};

Parser.prototype._onHandshake = function _onHandshake(body) {
  throw new Error('Should not be called');
};

Parser.prototype._onLink = function _onLink(body) {
  throw new Error('Should not be called');
};

Parser.prototype._onData = function _onData(body) {
  throw new Error('Should not be called');
};
