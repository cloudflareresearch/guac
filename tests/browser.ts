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
  grant_exchanges: z.array(z.tuple([hex, hex])),
  grant_state: hex.nullable(),
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
const responseType = 'application/mole-endorsement-response; type=0002';

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
  const outcome = pending.finish(update(test.update));
  if (test.expected_balance === null) {
    assert.deepEqual(outcome, { kind: 'consumed' });
  } else {
    assert.ok(outcome.kind === 'replaced');
    assert.equal(outcome.credential.balance, BigInt(test.expected_balance));
    outcome.credential.free();
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
    const configuration = new guac.AnchorConfig(Uint8Array.fromHex(anchor.public_key), Uint8Array.fromHex(anchor.epoch));
    const [[firstRequest, firstResponse], [secondRequest, secondResponse]] = test.grant_exchanges;
    const grant = guac.startGrant(configuration, 1);
    assert.equal(grant.request.toHex(), firstRequest);
    assert.throws(() => grant.advance(new Uint8Array(), 'text/plain'), { code: 'mismatch' });
    assert.deepEqual(grant.advance(Uint8Array.fromHex(firstResponse), responseType), { kind: 'continue' });
    assert.equal(grant.request.length, secondRequest.length / 2); // Fresh challenges, so only the size is known.
    grant.free();
    assert.ok(test.grant_state !== null);
    const resumed = guac.PendingGrant.fromStorageBytes(Uint8Array.fromHex(test.grant_state),
      Uint8Array.fromHex(secondRequest), configuration);
    const done = resumed.advance(Uint8Array.fromHex(secondResponse), responseType);
    assert.ok(done.kind === 'complete');
    assert.deepEqual(done.endorsements.map(endorsement => endorsement.toStorageBytes().toHex()),
      [test.endorsement_storage]);
    assert.throws(() => resumed.toStorageBytes(), { code: 'consumed' });
    done.endorsements.forEach(endorsement => endorsement.free());
    resumed.free();
    configuration.free();
    assert.ok(found);
    assert.equal(found.toStorageBytes().toHex(), test.endorsement_storage);
  }
  const endorsement = found;
  const redemption = test.redemption_challenge;
  if (endorsement) {
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
  if (endorsement) assert.throws(() => endorsement.toStorageBytes());
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
