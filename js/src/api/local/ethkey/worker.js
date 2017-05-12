// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

import { bytesToHex } from '~/api/util/format';
import { ethkey, allocate, ptr } from './ethkey.js';

const isWorker = typeof self !== 'undefined';

// Stay compatible between environments
if (!isWorker) {
  const scope = typeof global === 'undefined' ? window : global;

  scope.self = scope;
}

// keythereum should never be used outside of the browser
let keythereum = require('keythereum');

if (isWorker) {
  keythereum = self.keythereum;
}

function route ({ action, payload }) {
  if (action in actions) {
    return actions[action](payload);
  }

  return null;
}

// Pre-allocate buffers used to communicate with the WASM module.
const input = allocate(1024);
const secret = allocate(32);
const publicKey = allocate(64);
const address = allocate(20);

const actions = {
  phraseToWallet (phrase) {
    const phraseUtf8 = Buffer.from(phrase, 'utf8');

    input.set(phraseUtf8);

    ethkey.exports._brain(ptr(input), phraseUtf8.length, ptr(secret), ptr(address));

    const wallet = {
      secret: bytesToHex(secret),
      public: bytesToHex(publicKey),
      address: bytesToHex(address)
    };

    return wallet;
  },

  verifySecret (secret) {
    const key = Buffer.from(secret.slice(2), 'hex');

    secret.set(key);

    return ethkey.exports._verify_secret(ptr(secret));
  },

  createKeyObject ({ key, password }) {
    key = Buffer.from(key);
    password = Buffer.from(password);

    const iv = keythereum.crypto.randomBytes(16);
    const salt = keythereum.crypto.randomBytes(32);
    const keyObject = keythereum.dump(password, key, salt, iv);

    return JSON.stringify(keyObject);
  },

  decryptPrivateKey ({ keyObject, password }) {
    password = Buffer.from(password);

    try {
      const key = keythereum.recover(password, keyObject);

      // Convert to array to safely send from the worker
      return Array.from(key);
    } catch (e) {
      return null;
    }
  }
};

self.onmessage = function ({ data }) {
  try {
    const result = route(data);

    postMessage([null, result]);
  } catch (err) {
    console.error(err);
    postMessage([err.toString(), null]);
  }
};

// Emulate a web worker in Node.js
class KeyWorker {
  postMessage (data) {
    // Force async
    setTimeout(() => {
      try {
        const result = route(data);

        this.onmessage({ data: [null, result] });
      } catch (err) {
        this.onmessage({ data: [err, null] });
      }
    }, 0);
  }

  onmessage (event) {
    // no-op to be overriden
  }
}

if (exports != null) {
  exports.KeyWorker = KeyWorker;
}
