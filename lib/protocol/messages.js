'use strict';

const protobuf = require('protocol-buffers');

const p = protobuf(`
    message Open {
      required bytes feed = 1;
      required bytes nonce = 2;
    }

    message Handshake {
      required bytes id = 1;
      repeated string extensions = 2;
      required bytes signature = 3;
      repeated bytes chain = 4;
    }

    message Sync {
      required bytes filter = 1;
      required uint32 size = 2;
      required uint32 n = 3;
      required uint32 seed = 4;
      optional uint32 limit = 5;
    }

    message FilterOptions {
      required uint32 size = 1;
      required uint32 n = 1;
    }

    message Data {
      repeated bytes values = 1;
    }

    message Request {
      required bytes start  = 1;
      required bytes end = 2;
      optional uint32 limit = 3;
    }
`);

exports.id = {
  HANDSHAKE: 0,
  SYNC: 1,
  FILTER_OPTIONS: 2,
  DATA: 3,
  REQUEST: 4
};

exports.Open = p.Open;
exports.Handshake = p.Handshake;
exports.Sync = p.Sync;
exports.FilterOptions = p.FilterOptions;
exports.Data = p.Data;
exports.Request = p.Request;
