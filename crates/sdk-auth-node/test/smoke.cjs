const assert = require("node:assert/strict");
const { createHmac, randomUUID } = require("node:crypto");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const { NodeAuthService, migrateSqlite } = require("../sdk-auth-node.node");

async function main() {
  const database = join(tmpdir(), `sdk-auth-node-${randomUUID()}.db`);
  const realmId = randomUUID();
  const migration = migrateSqlite(database);
  assert.equal(migration.to, 6);
  const service = new NodeAuthService({
    sqlitePath: database,
    activeKeyId: "smoke-v1",
    vaultKeys: [{ keyId: "smoke-v1", material: Buffer.alloc(32, 0x5a) }],
    webauthnRealms: [
      {
        realmId,
        rpId: "example.com",
        rpName: "SDK Auth Smoke",
        origins: ["https://login.example.com"],
      },
    ],
  });
  assert.equal(typeof service.beginPasskeyLogin, "function");
  const registration = await service.register(
    realmId,
    "node@example.com",
    "correct horse battery staple",
  );

  await service.verifyEmail(realmId, registration.verificationToken);
  const outcome = await service.login(
    realmId,
    "NODE@example.com",
    "correct horse battery staple",
    false,
    { name: "node smoke test", networkHash: "test:local" },
    null,
  );
  assert.equal(outcome.kind, "authenticated");
  const authentication = outcome.authentication;
  assert.ok(authentication);
  assert.equal(
    await service.validateAccess(realmId, authentication.accessToken),
    registration.userId,
  );

  const enrollment = await service.beginTotpEnrollment(
    realmId,
    authentication.accessToken,
    "correct horse battery staple",
    "SDK Auth Smoke",
  );
  const activation = await service.confirmTotpEnrollment(
    realmId,
    authentication.accessToken,
    enrollment.enrollmentId,
    totp(enrollment.base32Secret),
    false,
  );
  const proofs = activation.recoveryCodes.values();
  const admin = () => ({
    realmId,
    accessToken: authentication.accessToken,
    password: "correct horse battery staple",
    proofKind: "recovery_code",
    secondFactor: proofs.next().value,
  });

  await service.bootstrapIam(admin());
  const permission = await service.registerPermission(
    admin(),
    "documents:read",
    "Read documents",
  );
  const role = await service.createRole(
    admin(),
    "document_reader",
    "Document reader",
    "Read-only document access",
  );
  assert.equal(
    await service.setRolePermission(admin(), role.id, permission.id, true),
    true,
  );
  const account = await service.createServiceAccount(
    admin(),
    "node-smoke-worker",
    "N-API contract test",
  );
  assert.equal(
    await service.setPrincipalRole(
      admin(),
      "service_account",
      account.id,
      role.id,
      true,
    ),
    true,
  );
  const key = await service.createApiKey(
    admin(),
    "service_account",
    account.id,
    "node-smoke-key",
    ["documents:read"],
    1,
  );
  const grant = await service.authorize(
    realmId,
    "api_key",
    key.credential,
    "documents:read",
  );
  assert.equal(grant.principalKind, "service_account");
  assert.equal(grant.principalId, account.id);
  assert.equal(
    (await service.listApiKeys(admin(), "service_account", account.id)).length,
    1,
  );
  assert.equal(await service.revokeApiKey(admin(), key.key.id), true);
  await assert.rejects(
    service.authorize(
      realmId,
      "api_key",
      key.credential,
      "documents:read",
    ),
  );

  await service.logout(realmId, authentication.accessToken);
  await assert.rejects(
    service.validateAccess(realmId, authentication.accessToken),
  );
}

function totp(base32Secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of base32Secret.replace(/=+$/u, "")) {
    const value = alphabet.indexOf(character.toUpperCase());
    assert.notEqual(value, -1);
    bits += value.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(Number.parseInt(bits.slice(offset, offset + 8), 2));
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
