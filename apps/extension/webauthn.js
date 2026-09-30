// Runs in the page's own JS world (so it can wrap navigator.credentials). It only forwards the
// request to lockbox's isolated content script and builds the credential object from the reply;
// keys and signing stay in the lockbox app. Anything lockbox doesn't handle goes to the browser.
(() => {
  const creds = navigator.credentials;
  if (!creds || !window.PublicKeyCredential || window.top !== window) return;
  const orig = { create: creds.create.bind(creds), get: creds.get.bind(creds) };

  const bytes = (buf) => (buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
  const b64 = (buf) => { let s = ''; for (const x of bytes(buf)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4)); const a = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i); return a.buffer; };

  let seq = 0;
  function ask(kind, data, signal) {
    return new Promise((resolve) => {
      const id = `lbx-${++seq}-${Math.random().toString(36).slice(2)}`;
      let acked = false;
      const finish = (result) => { window.removeEventListener('message', onMsg); resolve(result); };
      const onMsg = (e) => {
        if (e.source !== window || e.data?.id !== id) return;
        if (e.data.__lockbox === 'ack') acked = true;
        if (e.data.__lockbox === 'res') finish(e.data.result);
      };
      window.addEventListener('message', onMsg);
      // lockbox not reachable (extension reloading, restricted page): let the browser handle it
      setTimeout(() => { if (!acked) finish({ fallback: true }); }, 1000);
      signal?.addEventListener('abort', () => { window.postMessage({ __lockbox: 'abort', id }, location.origin); finish({ aborted: true }); });
      window.postMessage({ __lockbox: 'req', id, kind, data }, location.origin);
    });
  }

  function credential(r, response, ext, json) {
    return Object.create(PublicKeyCredential.prototype, {
      id: { value: r.id, enumerable: true }, rawId: { value: unb64(r.id), enumerable: true }, type: { value: 'public-key', enumerable: true },
      response: { value: response, enumerable: true }, authenticatorAttachment: { value: 'platform', enumerable: true },
      getClientExtensionResults: { value: () => ext }, toJSON: { value: () => ({ id: r.id, rawId: r.id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: ext, response: json }) },
    });
  }

  const fail = (r) => {
    if (r.aborted) return new DOMException('The operation was aborted.', 'AbortError');
    const [name, ...rest] = String(r.error).split(': ');
    return rest.length && /Error$/.test(name) ? new DOMException(rest.join(': '), name) : new DOMException(String(r.error || 'The request was declined.'), 'NotAllowedError');
  };

  creds.create = async function (opts) {
    const pk = opts?.publicKey;
    if (!pk) return orig.create(opts);
    const r = await ask('create', {
      rpId: pk.rp?.id || location.hostname, rpName: pk.rp?.name || '',
      userId: b64(pk.user.id), userName: pk.user.name || '', displayName: pk.user.displayName || '',
      challenge: b64(pk.challenge), algs: (pk.pubKeyCredParams || []).map((p) => p.alg),
      exclude: (pk.excludeCredentials || []).map((c) => b64(c.id)),
    }, opts.signal);
    if (r.fallback) return orig.create(opts);
    if (!r.response) throw fail(r);
    const x = r.response;
    const response = Object.create(AuthenticatorAttestationResponse.prototype, {
      clientDataJSON: { value: unb64(x.clientDataJSON), enumerable: true }, attestationObject: { value: unb64(x.attestationObject), enumerable: true },
      getAuthenticatorData: { value: () => unb64(x.authenticatorData) }, getPublicKey: { value: () => unb64(x.publicKey) },
      getPublicKeyAlgorithm: { value: () => x.publicKeyAlgorithm }, getTransports: { value: () => x.transports.slice() },
    });
    const ext = pk.extensions?.credProps ? { credProps: { rk: true } } : {};
    return credential(x, response, ext, { clientDataJSON: x.clientDataJSON, attestationObject: x.attestationObject, authenticatorData: x.authenticatorData, publicKey: x.publicKey, publicKeyAlgorithm: x.publicKeyAlgorithm, transports: x.transports });
  };

  creds.get = async function (opts) {
    const pk = opts?.publicKey;
    if (!pk) return orig.get(opts);
    const r = await ask('get', {
      rpId: pk.rpId || location.hostname, challenge: b64(pk.challenge),
      allow: (pk.allowCredentials || []).map((c) => b64(c.id)), conditional: opts.mediation === 'conditional',
    }, opts.signal);
    if (r.fallback) return orig.get(opts);
    if (!r.response) throw fail(r);
    const x = r.response;
    const response = Object.create(AuthenticatorAssertionResponse.prototype, {
      clientDataJSON: { value: unb64(x.clientDataJSON), enumerable: true }, authenticatorData: { value: unb64(x.authenticatorData), enumerable: true },
      signature: { value: unb64(x.signature), enumerable: true }, userHandle: { value: x.userHandle ? unb64(x.userHandle) : null, enumerable: true },
    });
    return credential(x, response, {}, { clientDataJSON: x.clientDataJSON, authenticatorData: x.authenticatorData, signature: x.signature, userHandle: x.userHandle });
  };
})();
