import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import * as guac from '../target/browser-web/guac.js';
import type { Endorsement } from '../target/browser-web/guac.js';

const wasm = guac.initSync({ module: readFileSync(join(import.meta.dirname, '../target/browser-web/guac_bg.wasm')) });

const hex = z.string().regex(/^(?:[0-9a-f]{2})*$/);
const Case = z.object({
  endpoint: z.string(),
  moderator_public: hex,
  balance_bits: z.number().int(),
  credential_context: hex,
  retention_seconds: z.string().regex(/^\d+$/),
  anchors: z.array(z.object({ public_key: hex, epoch: hex })),
  issuance_state: hex,
  issuance_state_raw: hex,
  issuance_request: z.string(),
  issuance_response: hex,
  credential_storage: hex,
  credential_raw: hex,
  presentation_challenge: hex,
  presentation: hex,
  pending_presentation: hex,
  presentation_state_raw: hex,
  update: hex,
  expected_balance: z.string().regex(/^\d+$/).nullable(),
  endorsement_storage: hex.nullable(),
  redemption_challenge: z.string(),
});
const corpus = z.object({ cases: z.array(Case) })
  .parse(JSON.parse(readFileSync(join(import.meta.dirname, 'vectors/transcripts.json'), 'utf8')));
const b64 = (hex: string): string => Uint8Array.fromHex(hex).toBase64({ alphabet: 'base64url', omitPadding: true });
const present = (hex: string): string => `Mole challenge-0001="${b64(hex)}"`;
const update = (hex: string): string => `update-0001="${b64(hex)}"`;

// Native transcripts own crypto combinations; Wasm owns JS value/ownership mapping.
const cases = [corpus.cases.find(test => test.anchors.length && test.expected_balance !== null),
  corpus.cases.find(test => !test.anchors.length && test.expected_balance === null)];
for (const test of cases) {
  assert.ok(test);
  const args = [test.endpoint, Uint8Array.fromHex(test.moderator_public), test.balance_bits,
    Uint8Array.fromHex(test.credential_context), BigInt(test.retention_seconds)] as const;
  const config = test.anchors.length
    ? guac.ModeratorConfig.withEndorsements(...args,
        Uint8Array.fromHex(test.anchors.map(anchor => anchor.public_key).join('')), Uint8Array.fromHex(test.anchors[0].epoch))
    : guac.ModeratorConfig.withoutEndorsement(...args);

  if (test.anchors.length) {
    assert.throws(() => guac.ModeratorConfig.withEndorsements(...args,
      Uint8Array.fromHex(test.anchors[0].public_key.repeat(3)), new Uint8Array(65535)),
      { code: 'configuration', message: /Anchor configuration too large/ });
  }

  assert.equal(config.endpoint, test.endpoint);
  assert.equal(config.moderatorDomain, new URL(test.endpoint).hostname);
  const issuance = guac.PendingIssuance.fromStorageBytes(Uint8Array.fromHex(test.issuance_state),
    test.issuance_request, config);
  assert.equal(issuance.authorization, test.issuance_request);
  assert.throws(() => issuance.finish(null), { code: 'missing' });
  const credential = issuance.finish(`response-0001="${b64(test.issuance_response)}"`);
  assert.equal(credential.toStorageBytes().toHex(), test.credential_storage);
  assert.equal(credential.balance, 8n);
  const exported = credential.toStorageBytes();
  exported.fill(0);
  assert.equal(credential.toStorageBytes().toHex(), test.credential_storage);

  // Local rejections are typed and leave the credential usable.
  const tooExpensive = Uint8Array.fromHex(test.presentation_challenge);
  new DataView(tooExpensive.buffer).setBigUint64(0, 9n);
  assert.throws(() => credential.present(present(tooExpensive.toHex())), { code: 'amount' });
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

  const pending = guac.PendingPresentation.fromStorageBytes(Uint8Array.fromHex(test.pending_presentation), config);
  assert.equal(pending.authorization, `Mole presentation-0001="${b64(test.presentation)}"`);
  assert.throws(() => pending.finish(null), { code: 'missing' }); // Missing is not explicit consumption.
  assert.equal(pending.toStorageBytes().toHex(), test.pending_presentation);
  if (test.expected_balance !== null) {
    const invalid = Uint8Array.fromHex(test.update);
    invalid[invalid.length - 1] ^= 1;
    assert.throws(() => pending.finish(update(invalid.toHex())));
    assert.equal(pending.toStorageBytes().toHex(), test.pending_presentation);
  }
  const replacement = pending.finish(update(test.update));
  if (test.expected_balance === null) {
    assert.equal(replacement, undefined);
  } else {
    assert.ok(replacement);
    assert.equal(replacement.balance, BigInt(test.expected_balance));
    replacement.free();
  }
  assert.throws(() => pending.finish(update(test.update)), { code: 'consumed' });
  assert.throws(() => pending.toStorageBytes());
  pending.free();

  let found: Endorsement | undefined;
  if (test.anchors.length) {
    const endorsementStorage = test.endorsement_storage;
    assert.ok(endorsementStorage !== null);
    const anchor = test.anchors.find(anchor => {
      const configuration = new guac.AnchorConfig(Uint8Array.fromHex(anchor.public_key), Uint8Array.fromHex(anchor.epoch));
      try {
        found = guac.Endorsement.fromStorageBytes(Uint8Array.fromHex(endorsementStorage), configuration);
        return true;
      } catch {
        return false;
      } finally {
        configuration.free();
      }
    });
    assert.ok(anchor);
    // A rejected response leaves the grant usable.
    const configuration = new guac.AnchorConfig(Uint8Array.fromHex(anchor.public_key), Uint8Array.fromHex(anchor.epoch));
    assert.throws(() => guac.startGrant(configuration, 1, 'bad_domain'), { code: 'configuration' });
    const grant = guac.startGrant(configuration, 1, config.moderatorDomain);
    assert.throws(() => grant.advance(new Uint8Array(), 'text/plain'), { code: 'mismatch' });
    assert.ok(grant.toStorageBytes().length);
    grant.free();
    configuration.free();
    assert.ok(found);
    assert.equal(found.moderatorDomain, config.moderatorDomain);
    assert.equal(found.toStorageBytes().toHex(), test.endorsement_storage);
  }
  const endorsement = found;
  const redemption = test.redemption_challenge;
  if (endorsement) {
    const keys = Uint8Array.fromHex(test.anchors.map(anchor => anchor.public_key).join(''));
    const epoch = Uint8Array.fromHex(test.anchors[0].epoch);
    assert.throws(() => guac.ModeratorConfig.withEndorsements('https://127.0.0.1/', args[1], args[2], args[3], args[4], keys, epoch), { code: 'configuration' });
    const other = guac.ModeratorConfig.withEndorsements('https://different.example/',
      args[1], args[2], args[3], args[4], keys, epoch);
    assert.throws(() => endorsement.requestCredential(other, redemption), { code: 'mismatch' });
    assert.equal(endorsement.moderatorDomain, config.moderatorDomain);
    other.free();
    assert.throws(() => endorsement.requestCredential(config, 'Mole redeem-0001=""'), { code: 'challenge' });
    assert.equal(endorsement.toStorageBytes().toHex(), test.endorsement_storage); // Still unspent.
  }
  const request = endorsement ? endorsement.requestCredential(config, redemption)
    : guac.requestCredential(config, redemption);
  assert.match(request.authorization, /^Mole redeem-000[12]="[\w-]*", credential-request-0001="[\w-]+"$/);
  const retry = guac.PendingIssuance.fromStorageBytes(request.toStorageBytes(), request.authorization, config);
  assert.equal(retry.authorization, request.authorization);
  assert.throws(() => guac.PendingIssuance.fromStorageBytes(request.toStorageBytes(), test.issuance_request, config),
    { code: 'mismatch' });
  retry.free();
  request.free();
  if (endorsement) {
    assert.throws(() => endorsement.toStorageBytes());
    assert.throws(() => endorsement.moderatorDomain, { code: 'consumed' });
  }
  assert.throws(() => guac.Credential.fromStorageBytes(new Uint8Array(), config));

  // Imported secrets are wiped from Wasm memory once decoded.
  guac.Credential.fromStorageBytes(Uint8Array.fromHex(test.credential_storage), config).free();
  config.free();

  // No client-only secret may remain anywhere in Wasm memory once everything is freed.
  // Not checked: k (the nullifier, public once presented), c/A/e (sent by the issuer)
  // and the spend amounts (low entropy). Offsets follow the act-rs encodings.
  const credential_raw = Uint8Array.fromHex(test.credential_raw); // k | c | r | A | e
  const issuance_raw = Uint8Array.fromHex(test.issuance_state_raw); // k | r | K
  const spend_raw = Uint8Array.fromHex(test.presentation_state_raw); // k* | r* | v1 | s | a | K'
  const secrets = {
    'credential r': credential_raw.subarray(40, 72),
    'issuance r': issuance_raw.subarray(32, 64),
    'spend k*': spend_raw.subarray(0, 32),
    'spend r*': spend_raw.subarray(32, 64),
  };
  const memory = Buffer.from(wasm.memory.buffer);
  for (const [name, scalar] of Object.entries(secrets)) {
    for (let i = 0; i + 8 <= scalar.length; i++) {
      assert.ok(!memory.includes(scalar.subarray(i, i + 8)), `${name} bytes ${i}..${i + 8} left in Wasm memory`);
    }
  }
}

console.log(`${cases.length} browser Wasm ABI transcripts passed`);
