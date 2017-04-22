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
      message Range {
        required bytes start  = 1;
        optional bytes end = 2;
      }

      required bytes filter = 1;
      required uint32 size = 2;
      required uint32 n = 3;
      required uint32 seed = 4;
      optional uint32 limit = 5;
      optional Range range = 6;
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
      optional bytes end = 2;
      optional uint32 limit = 3;
    }

    message Link {
      required bytes link  = 1;
    }
`);

exports.id = {
  HANDSHAKE: 0,
  SYNC: 1,
  FILTER_OPTIONS: 2,
  DATA: 3,
  REQUEST: 4,
  LINK: 5
};

exports.Open = p.Open;
exports.Handshake = p.Handshake;
exports.Sync = p.Sync;
exports.FilterOptions = p.FilterOptions;
exports.Data = p.Data;
exports.Request = p.Request;
exports.Link = p.Link;
