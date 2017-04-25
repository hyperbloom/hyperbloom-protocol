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
    const a = new Stream();
    const b = new Stream();

    bothSecure(a, b, cb);

    a.pipe(b);
    b.pipe(a);

    a.start({ feedKey: publicKey, privateKey, chain: [] });
    b.start({ feedKey: publicKey, privateKey, chain: [] });
  });

  it('should send request', (cb) => {
    const a = new Stream();
    const b = new Stream();

    let waiting = 2;
    const done = () => {
      if (--waiting === 0)
        return cb();
    };

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
        done();
      });
    });

    a.pipe(b);
    b.pipe(a);

    a.start({ feedKey: publicKey, privateKey, chain: [] });
    b.start({ feedKey: publicKey, privateKey, chain: [] });
    a.request({ start: Buffer.from('a') }, done);
  });

  it('should send chain', (cb) => {
    const chain = new HyperBloomChain({ root: publicKey });
    const bPair = signatures.keyPair();

    const links = [ chain.issueLink({
      expiration: Infinity,
      publicKey: bPair.publicKey
    }, privateKey) ];

    const a = new Stream();
    const b = new Stream();

    bothSecure(a, b, () => {
      cb();
    });

    a.pipe(b);
    b.pipe(a);

    a.start({ feedKey: publicKey, privateKey, chain: [] });
    b.start({
      feedKey: publicKey,
      privateKey: bPair.secretKey,
      chain: links
    });
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

    const a = new Stream();
    const b = new Stream();

    bothSecure(a, b, () => {
      a.on('chain-update', (chain) => {
        assert.equal(chain.length, 4);
        cb();
      });
    });

    a.pipe(b);
    b.pipe(a);

    a.start({
      feedKey: publicKey,
      privateKey: chainA.privateKey,
      chain: chainA.links
    });
    b.start({
      feedKey: publicKey,
      privateKey: chainB.privateKey,
      chain: chainB.links
    });
  });

  it('should support asynchronous start', (cb) => {
    const a = new Stream();
    a.start({ feedKey: publicKey, privateKey, chain: [] });
    const b = new Stream();

    b.on('open', (open) => {
      setTimeout(() => {
        b.start({
          feedKey: publicKey,
          privateKey,
          chain: []
        });

        bothSecure(a, b, cb);
      }, 100);
    });
    a.pipe(b);
    b.pipe(a);
  });
});
