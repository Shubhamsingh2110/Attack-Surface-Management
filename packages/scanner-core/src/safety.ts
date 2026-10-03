import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

export function canonicalizeDomain(input: string) {
  const value = input.trim().toLowerCase().replace(/^https?:\/\//i, "").split("/")[0].replace(/\.$/, "");
  const ascii = domainToASCII(value);
  if (!ascii || ascii.length > 253 || ascii.split(".").some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))) {
    throw new Error("Enter a valid domain name without a path.");
  }
  return ascii;
}

function ipv4Number(address: string) {
  return address.split(".").reduce((value, octet) => (value * 256) + Number(octet), 0) >>> 0;
}

function inV4Range(address: string, base: string, prefix: number) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4Number(address) & mask) === (ipv4Number(base) & mask);
}

export function isPublicIp(address: string) {
  const version = isIP(address);
  if (version === 4) {
    return ![
      ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
      ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
      ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
      ["224.0.0.0", 4], ["240.0.0.0", 4],
    ].some(([base, prefix]) => inV4Range(address, String(base), Number(prefix)));
  }
  if (version === 6) {
    const normalized = address.toLowerCase();
    if (normalized === "::" || normalized === "::1" || normalized.startsWith("2001:db8:") || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb") || normalized.startsWith("ff")) return false;
    if (normalized.startsWith("::ffff:")) return isPublicIp(normalized.slice(7));
    return true;
  }
  return false;
}

export async function resolvePublicAddresses(hostname: string) {
  const results = await lookup(hostname, { all: true, verbatim: true });
  const addresses = [...new Set(results.map((result) => result.address))];
  if (!addresses.length || addresses.some((address) => !isPublicIp(address))) {
    throw new Error("Target resolves to a blocked or non-public address.");
  }
  return addresses;
}
