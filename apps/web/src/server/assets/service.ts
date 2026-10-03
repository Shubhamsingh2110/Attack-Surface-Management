import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { ObjectId } from "mongodb";
import type { AssetCriticality, AssetType, ScanFrequency, VerificationMethod } from "@asm/contracts/assets";
import { collections, ensureIndexes } from "@asm/database";
import { canonicalizeDomain, fetchVerificationFile } from "@asm/scanner-core";
import * as dns from "node:dns/promises";

function digest(value: string) { return createHash("sha256").update(value).digest("hex"); }

function canonicalizeAsset(type: AssetType, input: string) {
  if (type === "domain" || type === "subdomain") return canonicalizeDomain(input);
  if (type === "ip") {
    const value = input.trim();
    if (!isIP(value)) throw new Error("Enter a valid IP address.");
    return value;
  }
  const value = input.trim();
  const [address, prefix] = value.split("/");
  const version = isIP(address);
  const prefixNumber = Number(prefix);
  if (!version || !Number.isInteger(prefixNumber) || prefixNumber < 0 || prefixNumber > (version === 4 ? 32 : 128)) throw new Error("Enter a valid CIDR range.");
  return `${address}/${prefixNumber}`;
}

export async function createAsset(input: { type: AssetType; value: string; displayName?: string; criticality: AssetCriticality; tags: string[]; scanFrequency: ScanFrequency; adminId: string }) {
  await ensureIndexes();
  const { assets } = await collections();
  if (await assets.countDocuments() >= 1_000) throw new Error("Asset inventory limit reached.");
  const value = canonicalizeAsset(input.type, input.value);
  const now = new Date();
  const result = await assets.insertOne({
    type: input.type, value, displayName: input.displayName, criticality: input.criticality,
    tags: [...new Set(input.tags.map((tag) => tag.toLowerCase()))], ownershipStatus: input.type === "domain" || input.type === "subdomain" ? "verified" : "pending",
    ...(input.type === "domain" || input.type === "subdomain" ? { verificationMethod: "passive_public" as const, verifiedAt: now } : {}), scanFrequency: input.scanFrequency,
    createdBy: new ObjectId(input.adminId), createdAt: now, updatedAt: now,
  });
  return result.insertedId;
}

export async function listAssets() {
  const { assets, ownershipChallenges } = await collections();
  const rows = await assets.find().sort({ createdAt: -1 }).limit(200).toArray();
  return Promise.all(rows.map(async (asset) => ({
    ...asset,
    _id: asset._id.toHexString(),
    latestChallenge: await ownershipChallenges.findOne({ assetId: asset._id, expiresAt: { $gt: new Date() } }, { sort: { createdAt: -1 } }),
  })));
}

export async function createOwnershipChallenge(assetId: string, method: VerificationMethod) {
  const { assets, ownershipChallenges } = await collections();
  const asset = await assets.findOne({ _id: new ObjectId(assetId) });
  if (!asset) throw new Error("Asset not found.");
  if (asset.ownershipStatus === "verified") throw new Error("Asset is already verified.");
  if (asset.type !== "domain" && asset.type !== "subdomain") throw new Error("Automated verification currently supports domain assets only.");
  const verificationValue = `asm-verification=${randomBytes(24).toString("base64url")}`;
  const now = new Date();
  await ownershipChallenges.insertOne({
    assetId: asset._id, method, tokenHash: digest(verificationValue), verificationValue,
    recordName: method === "dns_txt" ? `_asm-verification.${asset.value}` : `https://${asset.value}/.well-known/asm-verification.txt`,
    expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1_000), createdAt: now,
  });
}

export async function verifyAssetOwnership(assetId: string) {
  const { assets, ownershipChallenges } = await collections();
  const objectId = new ObjectId(assetId);
  const asset = await assets.findOne({ _id: objectId });
  const challenge = await ownershipChallenges.findOne({ assetId: objectId, expiresAt: { $gt: new Date() } }, { sort: { createdAt: -1 } });
  if (!asset || !challenge) throw new Error("Create a valid ownership challenge first.");
  let observed: string[] = [];
  if (challenge.method === "dns_txt") observed = (await dns.resolveTxt(challenge.recordName)).map((parts) => parts.join(""));
  else observed = [await fetchVerificationFile(asset.value)];
  if (!observed.some((value) => digest(value.trim()) === challenge.tokenHash)) throw new Error("Verification record was not found. DNS changes may take time to propagate.");
  const now = new Date();
  await assets.updateOne({ _id: objectId }, { $set: { ownershipStatus: "verified", verificationMethod: challenge.method, verifiedAt: now, updatedAt: now } });
  await ownershipChallenges.deleteMany({ assetId: objectId });
}

export async function attestPassiveScanAuthorization(assetId: string, authorizationBasis: string, adminId: string) {
  const { assets, ownershipChallenges } = await collections();
  const objectId = new ObjectId(assetId);
  const asset = await assets.findOne({ _id: objectId });
  if (!asset) throw new Error("Asset not found.");
  if (asset.type !== "domain" && asset.type !== "subdomain") throw new Error("Passive scanning currently supports domain assets only.");
  const now = new Date();
  await assets.updateOne({ _id: objectId }, { $set: {
    ownershipStatus: "verified", verificationMethod: "authorization_attestation",
    authorizationBasis, authorizationAttestedAt: now, verifiedAt: now, updatedAt: now,
  } });
  await ownershipChallenges.deleteMany({ assetId: objectId });
  return { asset: asset.value, actorId: new ObjectId(adminId) };
}
