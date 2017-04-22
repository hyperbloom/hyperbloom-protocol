'use strict';

const assert = require('assert');
const crypto = require('crypto');
const signatures = require('sodium-signatures');

const protocol = require('../');
const Stream = protocol.Stream;

describe('Stream', () => {
  it('should handshake', (cb) => {
    const keyPair = signatures.keyPair();
    const privateKey = keyPair.secretKey;
    const publicKey = keyPair.publicKey;

    const a = new Stream({ feedKey: publicKey, privateKey });
    const b = new Stream({ feedKey: publicKey, privateKey });

    let waiting = 2;
    function onSecure() {
      if (--waiting === 0)
        return cb();
    }
    a.on('secure', onSecure);
    b.on('secure', onSecure);

    a.pipe(b);
    b.pipe(a);
  });
});
