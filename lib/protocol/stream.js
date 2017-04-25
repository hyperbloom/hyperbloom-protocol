'use strict';

const assert = require('assert');
const debug = require('debug')('hyperbloom:protocol');
const util = require('util');
const sodium = require('sodium-universal');
const signatures = require('sodium-signatures');
const varint = require('varint');
const constants = require('hyperbloom-constants');
const HyperBloomChain = require('hyperbloom-chain');

const protocol = require('../protocol');
const messages = protocol.messages;
const Parser = protocol.Parser;

const Buffer = require('buffer').Buffer;

const PUBLIC_KEY_SIZE = constants.PUBLIC_KEY_SIZE;
const PRIVATE_KEY_SIZE = constants.PRIVATE_KEY_SIZE;
const ID_SIZE = constants.ID_SIZE;

const HASH_KEY = constants.HASH_KEY;
const HASH_SIZE = constants.HASH_SIZE;
const EMPTY_HASH = Buffer.alloc(HASH_SIZE);

const MAGIC = constants.MAGIC;

// X-Salsa 20 uses 192-bit nonce
const NONCE_SIZE = 24;

function Stream(options) {
  options = options || {};
  const id = options.id || this._randomBytes(ID_SIZE);
  assert.equal(id.length, ID_SIZE,
               `\`options.id\` must have size ${ID_SIZE}`);

  Parser.call(this, id);

  this.feedKey = null;
  this.feed = null;
  this.privateKey = null;
  this.chain = null;

  this.secure = false;
  this._hyperchain = null;
  this._startCallback = null;

  this._destroyed = false;

  // Needed to verify the handshake
  this._nonce ={
    remote: null,
    local: null,

    // Populated when both `Open` were sent/received
    hash: null,
    reverseHash: null
  };

  // Encryption state
  this._remote = {
    id: null,
    chain: null
  };

  // Queue of messages to be sent on `secure`
  this._queue = [];

  this.once('open', open => this._onOpen(open));
}
util.inherits(Stream, Parser);
module.exports = Stream;

Stream.prototype._randomBytes = function _randomBytes(size) {
  const res = Buffer.alloc(size);
  sodium.randombytes_buf(res);
  return res;
};

Stream.prototype._hash = function _hash(input) {
  const out = Buffer.alloc(HASH_SIZE);
  sodium.crypto_generichash(out, input, HASH_KEY);
  return out;
};

Stream.prototype._open = function _open() {
  debug('[%s] stream open', this._debugId);

  const nonce = this._randomBytes(NONCE_SIZE);
  this._nonce.local = nonce;

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
  // XXX: store nonce, otherwise it gets GCed
  // See: https://github.com/sodium-friends/sodium-native/pull/21
  this._xor.self.nonce = nonce;
};

Stream.prototype._send = function _send(id, Type, content, callback) {
  const idLen = varint.encodingLength(id);
  const msgLen = Type.encodingLength(content);

  debug('[%s] stream send id=%d size=%d', this._debugId, id, msgLen);

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

  // We can't quite guarantee that the write will go through by then, but
  // what else can we do?
  if (callback)
    process.nextTick(callback, null);
};

Stream.prototype._handshake = function _handshake(remoteNonce) {
  this._send(messages.id.HANDSHAKE, messages.Handshake, {
    id: this.id,
    chain: this.chain,
    signature: signatures.sign(this._nonce.hash, this.privateKey)
  });
};

Stream.prototype._onOpen = function _onOpen(open) {
  // NOTE: `open` is emitted by `Parser`
  this._onStart(() => {
    if (!open.feed.equals(this.feed))
      return this.emit('error', new Error('Feed mismatch'));

    this._nonce.remote = open.nonce;
    this._nonce.hash = this._hash(Buffer.concat([
      this._nonce.local, this._nonce.remote
    ]));
    this._nonce.reverseHash = this._hash(Buffer.concat([
      this._nonce.remote, this._nonce.local
    ]));
    this._nonce.local = null;
    this._nonce.remote = null;

    this._xor.remote = sodium.crypto_stream_xor_instance(open.nonce,
                                                         this.feedKey);
    // XXX: store nonce, otherwise it gets GCed
    // See: https://github.com/sodium-friends/sodium-native/pull/21
    this._xor.remote.nonce = open.nonce;

    this._handshake(open.nonce);

    this._resumeParsing();
  });
};

Stream.prototype._onStart = function _onStart(callback) {
  if (this.feed)
    return process.nextTick(callback);

  this._startCallback = callback;
};

Stream.prototype._onHandshake = function _onHandshake(body) {
  this._hyperchain.verify(body.chain, this._nonce.reverseHash, body.signature);

  this._remote.id = body.id;
  this._remote.chain = body.chain;

  this.secure = true;
  this.emit('secure', { id: body.id, chain: body.chain });

  const queue = this._queue;
  this._queue = null;
  queue.forEach(cb => cb());

  // Issue a Trust Link if needed
  if (this._remote.chain.length - 1 <= this.chain.length)
    return;

  // XXX: doing the work twice here, the links were already parsed above
  let expiration = Infinity;
  let publicKey;
  for (let i = 0; i < this._remote.chain.length; i++) {
    const link = this._hyperchain.parseLink(this._remote.chain[i]);
    expiration = Math.min(expiration, link.expiration);
    publicKey = link.publicKey;
  }

  const link = this._hyperchain.issueLink({
    expiration: expiration,
    publicKey: publicKey
  }, this.privateKey);
  this._secureSend(messages.id.LINK, messages.Link, { link });
};

Stream.prototype._onLink = function _onLink(body) {
  if (this.chain.length - 1 <= this._remote.chain.length)
    return;

  // Construct shorter chain
  const chain = this._remote.chain.concat(body.link);

  // Verify it
  const sign = signatures.sign(EMPTY_HASH, this.privateKey);
  this._hyperchain.verify(chain, EMPTY_HASH, sign);

  // Update
  this.chain = chain;
  this.emit('chain-update', chain);
};

Stream.prototype._secureSend = function _secureSend(id, Type, content,
                                                    callback) {
  // Just to validate that all required fields are present
  Type.encodingLength(content);

  if (!this.secure) {
    this._queue.push(() => this._secureSend(id, Type, content, callback));
    return;
  }

  this._send(id, Type, content, callback);
};

// Public API

Stream.prototype.start = function start(options) {
  options = Object.assign({}, options);

  // Validation
  assert(Buffer.isBuffer(options.feedKey),
         '\`options.feedKey\` must be a Buffer');
  assert.equal(options.feedKey.length, PUBLIC_KEY_SIZE,
               `\`options.feedKey\` must have size ${PUBLIC_KEY_SIZE}`);
  assert(Buffer.isBuffer(options.privateKey),
         '`options.privateKey` must be a Buffer');
  assert.equal(options.privateKey.length, PRIVATE_KEY_SIZE,
               `\`options.privateKey\` must have size ${PRIVATE_KEY_SIZE}`);

  assert(Array.isArray(options.chain), 'options.chain must be an Array');
  assert(options.chain.length <= constants.MAX_CHAIN_LENGTH,
         `Maximum chain length size is ${constants.MAX_CHAIN_LENGTH}`);

  this.feedKey = options.feedKey;
  this.feed = options.discoveryKey || this._hash(this.feedKey);
  assert.equal(this.feed.length, HASH_SIZE,
               `\`options.discoverKey\` must have size ${HASH_SIZE}`);

  // Init
  this.privateKey = options.privateKey;

  this.chain = options.chain;
  this._hyperchain = new HyperBloomChain({ root: this.feedKey });

  // Verify chain early
  {
    const sign = signatures.sign(EMPTY_HASH, this.privateKey);
    this._hyperchain.verify(this.chain, EMPTY_HASH, sign);
  }

  this._open();

  if (this._startCallback !== null) {
    const cb = this._startCallback;
    process.nextTick(cb);
  }
};

Stream.prototype.destroy = function destroy(err) {
  if (this._destroyed)
    return;

  // no-op for now
  this._destroyed = true;
  this.emit('close');
};

Stream.prototype.sync = function sync(body, callback) {
  this._secureSend(messages.id.SYNC, messages.Sync, body, callback);
};

Stream.prototype.filterOptions = function filterOptions(body, callback) {
  this._secureSend(messages.id.FILTER_OPTIONS, messages.FilterOptions, body,
                   callback);
};

Stream.prototype.data = function data(body, callback) {
  this._secureSend(messages.id.DATA, messages.Data, body, callback);
};

Stream.prototype.request = function request(body, callback) {
  this._secureSend(messages.id.REQUEST, messages.Request, body, callback);
};
