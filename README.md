# Keyring

**Named testnet identities kept in the browser.** Add a key under a name on the page, pick it from any app that imports the module. One keyring instead of every app importing keys on its own.

Live: https://melvincarvalho.github.io/keyring/

Keys are stored plain in `localStorage['keyring']` as `[{ name, priv }]`, priv as 64 hex chars. Testnet only. Never add a key that holds real coins.

## From an app

```js
import { list, get, add, remove, info, parsePrivateKey } from 'https://melvincarvalho.github.io/keyring/keyring.js';

list();               // [{ name, priv }]
get('alice');         // { name, priv } or undefined
add('bob', 'nsec1…'); // hex, nsec or WIF; returns { npub, nsec, tb1p, bc1p, xonly }
info(priv);           // same derived view for any hex key
window.addEventListener('keyring', render);   // changed in this tab
window.addEventListener('storage', render);   // changed in another tab
```

Apps on the same origin share the keyring. Apps on other origins each have their own copy; export and import JSON on the page to move keys across.

The address model matches blaketest and Fid: the x-only pubkey is the taproot witness program untweaked, so the npub and the `tb1p` address are the same key.
