const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const guac = require('../target/browser-node/guac.js');
const corpus = JSON.parse(readFileSync(join(__dirname, 'vectors/transcripts.json')));
const bytes = hex => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = bytes => Buffer.from(bytes).toString('hex');
const b64 = hex => Buffer.from(hex, 'hex').toString('base64url');
const present = hex => `Mole challenge-0001="${b64(hex)}"`;
const update = hex => `update-0001="${b64(hex)}"`;

// Native transcripts own crypto combinations; Wasm owns JS value/ownership mapping.
const cases = [corpus.cases.find(test => test.anchors.length && test.expected_balance !== null),
  corpus.cases.find(test => !test.anchors.length && test.expected_balance === null)];
for (const test of cases) {
  assert.ok(test);
  const args = [test.endpoint, bytes(test.moderator_public), test.balance_bits,
    bytes(test.credential_context), BigInt(test.retention_seconds)];
  const config = test.anchors.length
    ? guac.ModeratorConfig.withEndorsements(...args,
        bytes(test.anchors.map(anchor => anchor.public_key).join('')), bytes(test.anchors[0].epoch))
    : guac.ModeratorConfig.withoutEndorsement(...args);

  if (test.anchors.length) {
    assert.throws(() => guac.ModeratorConfig.withEndorsements(...args,
      bytes(test.anchors[0].public_key.repeat(3)), new Uint8Array(65535)),
      { code: 'configuration', message: /Anchor configuration too large/ });
  }

  assert.equal(config.endpoint, test.endpoint);
  const issuance = guac.PendingIssuance.fromStorageBytes(bytes(test.issuance_state),
    test.issuance_request, config);
  assert.equal(issuance.authorization, test.issuance_request);
  assert.throws(() => issuance.finish(null), { code: 'missing' });
  const credential = issuance.finish(`response-0001="${b64(test.issuance_response)}"`);
  assert.equal(hex(credential.toStorageBytes()), test.credential_storage);
  assert.equal(credential.balance, 8n);
  const exported = credential.toStorageBytes();
  exported.fill(0);
  assert.equal(hex(credential.toStorageBytes()), test.credential_storage);

  // Local rejections are typed and leave the credential usable.
  const tooExpensive = bytes(test.presentation_challenge);
  new DataView(tooExpensive.buffer).setBigUint64(0, 9n);
  assert.throws(() => credential.present(present(hex(tooExpensive))), { code: 'amount' });
  assert.throws(() => credential.present('Mole endorse-0002=""'), { code: 'challenge' });
  assert.equal(credential.balance, 8n);

  // Unsupported challenges are skipped in favour of a usable one.
  const fresh = credential.present(`Basic realm="x", Mole challenge-0099="AA", ${present(test.presentation_challenge)}`);
  assert.throws(() => credential.toStorageBytes(), { code: 'consumed' }); // Spent credentials cannot be reused.
  credential.free();
  const freshState = fresh.toStorageBytes();
  const restored = guac.PendingPresentation.fromStorageBytes(freshState, config);
  assert.equal(restored.authorization, fresh.authorization);
  assert.match(fresh.recoveryAuthorization, /^Mole recovery-0001="[\w-]{128}"$/);
  restored.free();
  fresh.free();

  const pending = guac.PendingPresentation.fromStorageBytes(bytes(test.pending_presentation), config);
  assert.equal(pending.authorization, `Mole presentation-0001="${b64(test.presentation)}"`);
  assert.throws(() => pending.finish(null), { code: 'missing' }); // Missing is not explicit consumption.
  assert.equal(hex(pending.toStorageBytes()), test.pending_presentation);
  if (test.expected_balance !== null) {
    const invalid = bytes(test.update);
    invalid[invalid.length - 1] ^= 1;
    assert.throws(() => pending.finish(update(hex(invalid))));
    assert.equal(hex(pending.toStorageBytes()), test.pending_presentation);
  }
  const replacement = pending.finish(update(test.update));
  if (test.expected_balance === null) {
    assert.equal(replacement, undefined);
  } else {
    assert.equal(replacement.balance, BigInt(test.expected_balance));
    replacement.free();
  }
  assert.throws(() => pending.finish(update(test.update)), { code: 'consumed' });
  assert.throws(() => pending.toStorageBytes());
  pending.free();

  let endorsement;
  if (test.anchors.length) {
    const anchor = test.anchors.find(anchor => {
      const configuration = new guac.AnchorConfig(bytes(anchor.public_key), bytes(anchor.epoch));
      try {
        endorsement = guac.Endorsement.fromStorageBytes(bytes(test.endorsement_storage), configuration);
        return true;
      } catch {
        return false;
      } finally {
        configuration.free();
      }
    });
    assert.ok(anchor);
    assert.equal(hex(endorsement.toStorageBytes()), test.endorsement_storage);
  }
  const redemption = test.redemption_challenge;
  if (endorsement) {
    assert.throws(() => endorsement.requestCredential(config, 'Mole redeem-0001=""'), { code: 'challenge' });
    assert.equal(hex(endorsement.toStorageBytes()), test.endorsement_storage); // Still unspent.
  }
  const request = endorsement ? endorsement.requestCredential(config, redemption)
    : guac.requestCredential(config, redemption);
  assert.match(request.authorization, /^Mole redeem-000[12]="[\w-]*", credential-request-0001="[\w-]+"$/);
  const retry = guac.PendingIssuance.fromStorageBytes(request.toStorageBytes(), request.authorization, config);
  assert.equal(retry.authorization, request.authorization);
  retry.free();
  request.free();
  if (endorsement) assert.throws(() => endorsement.toStorageBytes());
  assert.throws(() => guac.Credential.fromStorageBytes(new Uint8Array(), config));

  // Imported secrets are wiped from Wasm memory once decoded.
  const stored = bytes(test.credential_storage);
  const set = Uint8Array.prototype.set;
  let copy;
  Uint8Array.prototype.set = function (source, offset) {
    if (source === stored) copy = { memory: this, offset };
    return set.call(this, source, offset);
  };
  try { guac.Credential.fromStorageBytes(stored, config).free(); }
  finally { Uint8Array.prototype.set = set; }
  assert.ok(copy);
  // The freed chunk may hold allocator metadata; no 8-byte run of the secret payload may remain.
  const residual = copy.memory.slice(copy.offset, copy.offset + stored.length);
  for (let i = 46; i + 8 <= stored.length; i += 8) {
    assert.notDeepEqual(residual.subarray(i, i + 8), stored.subarray(i, i + 8));
  }
  config.free();
}

console.log(`${cases.length} browser Wasm ABI transcripts passed`);
