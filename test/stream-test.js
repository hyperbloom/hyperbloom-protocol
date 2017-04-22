'use strict';

const assert = require('assert');
const crypto = require('crypto');
const signatures = require('sodium-signatures');

const protocol = require('../');
const Stream = protocol.Stream;

describe('Stream', () => {
  it('should handshake', () => {
    const keyPair = signatures.keyPair();
    const privateKey = keyPair.secretKey;
    const publicKey = keyPair.publicKey;

    const a = new Stream({ feedKey: publicKey, privateKey });
    const b = new Stream({ feedKey: publicKey, privateKey });

    a.pipe(b);
    b.pipe(a);
  });
});
