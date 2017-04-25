# HyperBloom Protocol

Implementation of HyperBloom Protocol. See [specification][0] for protocol
details.

## Usage

```js
const Stream = require('hyperbloom-protocol').Stream;

const s = new Stream();

socket.pipe(s);
s.pipe(socket);

s.on('open', ({ feed }) => {
});

s.start({
  feedKey: feedKey,
  privateKey: privateKey,
  chain: [ /* trust chain */ ]
});

s.on('secure', () => {
  // Send various messages
  s.request({ start: Buffer.from('a'), end: Buffer.from('z'), limit: 10 });
  s.sync({ /* bloom filter */ });
  s.filterOptions({ /* bloom filter options */ });
  s.data([ Buffer.from('value') ], () => {});

  // Receive messages
  s.on('message', (message) => {
    console.log(message.type, message.body);
  });

  // Destroy stream
  s.destroy();
});
```

## Chain

See [hyperbloom-trust][1] and [hyperbloom-chain][2].

## LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2017.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: https://github.com/hyperbloom/hyperbloom-protocol/blob/master/spec.md
[1]: https://github.com/hyperbloom/hyperbloom-trust
[2]: https://github.com/hyperbloom/hyperbloom-chain
