'use strict';

const assert = require('assert');
const crypto = require('crypto');
const signatures = require('sodium-signatures');
const HyperBloomChain = require('hyperbloom-chain');

const protocol = require('../');
const Stream = protocol.Stream;

describe('Stream', () => {
  const keyPair = signatures.keyPair();
  const privateKey = keyPair.secretKey;
  const publicKey = keyPair.publicKey;

  function bothSecure(a, b, cb) {
    let waiting = 2;
    function onSecure() {
      assert(waiting > 0);
      if (--waiting === 0)
        return cb();
    }
    a.on('secure', onSecure);
    b.on('secure', onSecure);
  }

  it('should handshake', (cb) => {
    const a = new Stream({ feedKey: publicKey, privateKey, chain: [] });
    const b = new Stream({ feedKey: publicKey, privateKey, chain: [] });

    bothSecure(a, b, cb);

    a.pipe(b);
    b.pipe(a);
  });

  it('should send request', (cb) => {
    const a = new Stream({ feedKey: publicKey, privateKey, chain: [] });
    const b = new Stream({ feedKey: publicKey, privateKey, chain: [] });

    bothSecure(a, b, () => {
      b.on('message', (msg) => {
        assert.deepEqual(msg, {
          type: 'request',
          body: {
            start: Buffer.from('a'),
            end: null,
            limit: 0
          }
        });
        cb();
      });
    });

    a.pipe(b);
    b.pipe(a);

    a.request({ start: Buffer.from('a') });
  });

  it('should send chain', (cb) => {
    const chain = new HyperBloomChain({ root: publicKey });
    const bPair = signatures.keyPair();

    const links = [ chain.issueLink({
      expiration: Infinity,
      publicKey: bPair.publicKey
    }, privateKey) ];

    const a = new Stream({ feedKey: publicKey, privateKey, chain: [] });
    const b = new Stream({
      feedKey: publicKey,
      privateKey: bPair.secretKey,
      chain: links
    });

    bothSecure(a, b, () => {
      cb();
    });

    a.pipe(b);
    b.pipe(a);
  });
});
