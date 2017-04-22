'use strict';

const assert = require('assert');
const crypto = require('crypto');

const protocol = require('../');
const Stream = protocol.Stream;

describe('Stream', () => {
  it('should handshake', () => {
    const key = crypto.randomBytes(32);
    const a = new Stream({ publicKey: key });
    const b = new Stream({ publicKey: key });

    a.pipe(b);
    b.pipe(a);
  });
});
