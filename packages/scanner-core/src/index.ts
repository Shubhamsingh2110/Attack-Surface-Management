import * as dns from "node:dns/promises";
import * as http from "node:http";
import * as https from "node:https";
import * as tls from "node:tls";
import { resolvePublicAddresses } from "./safety";

async function settled<T>(operation: () => Promise<T>): Promise<T | null> {
  try { return await operation(); } catch { return null; }
}

export async function scanDns(hostname: string) {
  const [a, aaaa, mx, ns, txt, cname] = await Promise.all([
    settled(() => dns.resolve4(hostname)), settled(() => dns.resolve6(hostname)),
    settled(() => dns.resolveMx(hostname)), settled(() => dns.resolveNs(hostname)),
    settled(() => dns.resolveTxt(hostname)), settled(() => dns.resolveCname(hostname)),
  ]);
  const publicAddresses = await resolvePublicAddresses(hostname);
  return { a, aaaa, mx, ns, txt, cname, publicAddresses };
}

export async function scanTls(hostname: string) {
  const [address] = await resolvePublicAddresses(hostname);
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    const socket = tls.connect({ host: address, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 8_000 }, () => {
      const certificate = socket.getPeerCertificate();
      const result = {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ?? null,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        subject: certificate.subject ?? null,
        issuer: certificate.issuer ?? null,
        validFrom: certificate.valid_from ?? null,
        validTo: certificate.valid_to ?? null,
        fingerprint256: certificate.fingerprint256 ?? null,
        subjectAltName: certificate.subjectaltname ?? null,
      };
      socket.end();
      resolve(result);
    });
    socket.once("timeout", () => socket.destroy(new Error("TLS connection timed out.")));
    socket.once("error", reject);
  });
}

async function pinnedRequest(hostname: string, path: string, method: "GET" | "HEAD") {
  const [address] = await resolvePublicAddresses(hostname);
  const makeRequest = hostname === address && address.includes(":") ? https : https;
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const request = makeRequest.request({
      hostname,
      servername: hostname,
      port: 443,
      path,
      method,
      headers: { "User-Agent": "ASM-Control/1.0", Accept: "text/plain,text/html;q=0.8" },
      lookup: (_host, _options, callback) => callback(null, address, address.includes(":") ? 6 : 4),
      timeout: 8_000,
      rejectUnauthorized: true,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { if (body.length < 16_384) body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: body.slice(0, 16_384) }));
    });
    request.once("timeout", () => request.destroy(new Error("HTTP request timed out.")));
    request.once("error", reject);
    request.end();
  });
}

export async function scanHttp(hostname: string) {
  const response = await pinnedRequest(hostname, "/", "HEAD");
  const headers = response.headers;
  const securityHeaders = {
    strictTransportSecurity: headers["strict-transport-security"] ?? null,
    contentSecurityPolicy: headers["content-security-policy"] ?? null,
    xContentTypeOptions: headers["x-content-type-options"] ?? null,
    xFrameOptions: headers["x-frame-options"] ?? null,
    referrerPolicy: headers["referrer-policy"] ?? null,
    permissionsPolicy: headers["permissions-policy"] ?? null,
  };
  const technologies = [headers.server && `Server: ${headers.server}`, headers["x-powered-by"] && `Powered by: ${headers["x-powered-by"]}`].filter(Boolean);
  return { status: response.status, location: headers.location ?? null, securityHeaders, technologies };
}

export async function fetchVerificationFile(hostname: string) {
  return (await pinnedRequest(hostname, "/.well-known/asm-verification.txt", "GET")).body.trim();
}

export async function postJsonToPublicUrl(target: string, body: unknown, headers: Record<string, string> = {}) {
  const url = new URL(target);
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("Integration endpoints must be HTTPS URLs without embedded credentials.");
  const [address] = await resolvePublicAddresses(url.hostname);
  const payload = Buffer.from(JSON.stringify(body));
  if (payload.length > 64 * 1024) throw new Error("Integration payload exceeds 64 KiB.");
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const request = https.request({
      hostname: url.hostname, servername: url.hostname, port: url.port ? Number(url.port) : 443,
      path: `${url.pathname}${url.search}`, method: "POST",
      headers: { "User-Agent": "ASM-Control/1.0", Accept: "application/json", "Content-Type": "application/json", "Content-Length": String(payload.length), ...headers },
      lookup: (_host, _options, callback) => callback(null, address, address.includes(":") ? 6 : 4),
      timeout: 10_000, rejectUnauthorized: true,
    }, (response) => {
      let responseBody = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { if (responseBody.length < 4_096) responseBody += chunk; });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, body: responseBody.slice(0, 4_096) }));
    });
    request.once("timeout", () => request.destroy(new Error("Integration request timed out.")));
    request.once("error", reject);
    request.end(payload);
  });
}

export async function scanCertificateTransparency(hostname: string) {
  const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`, { signal: AbortSignal.timeout(10_000), headers: { Accept: "application/json", "User-Agent": "ASM-Control/1.0" } });
  if (!response.ok) throw new Error(`Certificate Transparency provider returned ${response.status}.`);
  const rows = await response.json() as Array<{ name_value?: string; issuer_name?: string; not_before?: string; not_after?: string }>;
  const names = [...new Set(rows.flatMap((row) => (row.name_value ?? "").split("\n")).map((name) => name.replace(/^\*\./, "").toLowerCase()).filter((name) => name === hostname || name.endsWith(`.${hostname}`)))].slice(0, 500);
  return { names, certificateCount: rows.length, sampledIssuers: [...new Set(rows.map((row) => row.issuer_name).filter(Boolean))].slice(0, 20) };
}

export async function scanRdap(hostname: string) {
  const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(hostname)}`, { signal: AbortSignal.timeout(10_000), headers: { Accept: "application/rdap+json, application/json", "User-Agent": "ASM-Control/1.0" } });
  if (!response.ok) throw new Error(`RDAP provider returned ${response.status}.`);
  const data = await response.json() as Record<string, unknown>;
  return { handle: data.handle ?? null, ldhName: data.ldhName ?? null, status: data.status ?? null, events: data.events ?? null, nameservers: data.nameservers ?? null, secureDNS: data.secureDNS ?? null };
}

export { canonicalizeDomain, isPublicIp, resolvePublicAddresses } from "./safety";
