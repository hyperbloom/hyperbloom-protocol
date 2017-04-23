'use strict';

const assert = require('assert');
const crypto = require('crypto');
const signatures = require('sodium-signatures');
const HyperBloomChain = require('hyperbloom-chain');

const protocol = require('../');
const Stream = protocol.Stream;
const Parser = protocol.Parser;

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

  it('should construct shorter chain', (cb) => {
    const chain = new HyperBloomChain({ root: publicKey });

    function construct(privateKey, expirations) {
      const links = [];
      for (let i = 0; i < expirations.length; i++) {
        const pair = signatures.keyPair();

        const link = chain.issueLink({
          expiration: expirations[i],
          publicKey: pair.publicKey
        }, privateKey);
        links.push(link);

        privateKey = pair.secretKey;
      }

      return { privateKey, links };
    }

    const now = Date.now() / 1000;

    const shared = construct(privateKey, [ now + 5000, now + 4000 ]);
    const chainA = construct(shared.privateKey, [
      now + 3000, now + 2000, now + 1000
    ]);
    const chainB = construct(shared.privateKey, [ now + 5000 ]);

    chainA.links = shared.links.concat(chainA.links);
    chainB.links = shared.links.concat(chainB.links);

    const a = new Stream({
      feedKey: publicKey,
      privateKey: chainA.privateKey,
      chain: chainA.links
    });
    const b = new Stream({
      feedKey: publicKey,
      privateKey: chainB.privateKey,
      chain: chainB.links
    });

    bothSecure(a, b, () => {
      a.on('chain-update', (chain) => {
        assert.equal(chain.length, 4);
        cb();
      });
    });

    a.pipe(b);
    b.pipe(a);
  });

  it('should support pre-parse', (cb) => {
    const a = new Stream({ feedKey: publicKey, privateKey, chain: [] });
    const preB = new Parser();

    preB.on('open', (open, extra) => {
      setTimeout(() => {
        const b = new Stream({
          feedKey: publicKey,
          privateKey,
          chain: [],
          preparse: { open, extra }
        });

        bothSecure(a, b, cb);

        b.pipe(a);
        a.unpipe(preB);
        a.pipe(b);
      }, 100);
    });
    a.pipe(preB);
  });
});
