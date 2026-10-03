import * as dns from "node:dns/promises";
import * as http from "node:http";
import * as https from "node:https";
import * as tls from "node:tls";
import type { LookupFunction } from "node:net";
import { resolvePublicAddresses } from "./safety";

async function settled<T>(operation: () => Promise<T>): Promise<T | null> {
  try { return await operation(); } catch { return null; }
}

function pinnedLookup(address: string): LookupFunction {
  return (_hostname, options, callback) => {
    const family = address.includes(":") ? 6 : 4;
    if (options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

export async function scanDns(hostname: string) {
  const [a, aaaa, mx, ns, txt, cname, dmarcTxt] = await Promise.all([
    settled(() => dns.resolve4(hostname)), settled(() => dns.resolve6(hostname)),
    settled(() => dns.resolveMx(hostname)), settled(() => dns.resolveNs(hostname)),
    settled(() => dns.resolveTxt(hostname)), settled(() => dns.resolveCname(hostname)), settled(() => dns.resolveTxt(`_dmarc.${hostname}`)),
  ]);
  const publicAddresses = await resolvePublicAddresses(hostname);
  const rootTxt = (txt ?? []).map((parts) => parts.join(""));
  const dmarcRecords = (dmarcTxt ?? []).map((parts) => parts.join("")).filter((record) => /^v=DMARC1\s*;/i.test(record));
  const spfRecords = rootTxt.filter((record) => /^v=spf1(?:\s|$)/i.test(record));
  return { a, aaaa, mx, ns, txt, cname, publicAddresses, emailSecurity: { spfRecords, dmarcRecords, dmarcRecordName: `_dmarc.${hostname}` } };
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
        serialNumber: certificate.serialNumber ?? null,
        keyBits: certificate.bits ?? null,
        isCertificateAuthority: certificate.ca ?? false,
      };
      socket.end();
      resolve(result);
    });
    socket.once("timeout", () => socket.destroy(new Error("TLS connection timed out.")));
    socket.once("error", reject);
  });
}

async function pinnedRequest(hostname: string, path: string, method: "GET" | "HEAD", maxBodyBytes = 16_384) {
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
      lookup: pinnedLookup(address),
      timeout: 8_000,
      rejectUnauthorized: true,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { if (body.length < maxBodyBytes) body += chunk; });
      response.on("end", () => resolve({ status: response.statusCode ?? 0, headers: response.headers, body: body.slice(0, maxBodyBytes) }));
    });
    request.once("timeout", () => request.destroy(new Error("HTTP request timed out.")));
    request.once("error", reject);
    request.end();
  });
}

export async function scanHttp(hostname: string) {
  let currentHostname = hostname;
  let currentPath = "/";
  const redirectChain: string[] = [];
  let response = await pinnedRequest(currentHostname, currentPath, "GET");
  for (let redirects = 0; redirects < 3 && response.status >= 300 && response.status < 400 && response.headers.location; redirects += 1) {
    const destination = new URL(response.headers.location, `https://${currentHostname}${currentPath}`);
    const relatedHostname = destination.hostname === hostname || destination.hostname.endsWith(`.${hostname}`) || hostname.endsWith(`.${destination.hostname}`);
    if (destination.protocol !== "https:" || !relatedHostname) break;
    redirectChain.push(destination.toString());
    currentHostname = destination.hostname;
    currentPath = `${destination.pathname}${destination.search}`;
    response = await pinnedRequest(currentHostname, currentPath, "GET");
  }
  const headers = response.headers;
  const securityHeaders = {
    strictTransportSecurity: headers["strict-transport-security"] ?? null,
    contentSecurityPolicy: headers["content-security-policy"] ?? null,
    xContentTypeOptions: headers["x-content-type-options"] ?? null,
    xFrameOptions: headers["x-frame-options"] ?? null,
    referrerPolicy: headers["referrer-policy"] ?? null,
    permissionsPolicy: headers["permissions-policy"] ?? null,
  };
  const generator = response.body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1]
    ?? response.body.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i)?.[1];
  const publicAssets = [...response.body.matchAll(/(?:src|href)=["']([^"']+)["']/gi)].map((match) => match[1]).filter(Boolean);
  const reactBundle = publicAssets.find((path) => /react-dom[^/]*\.js(?:\?|$)/i.test(path));
  let reactVersion: string | undefined;
  if (reactBundle) {
    try {
      const bundleUrl = new URL(reactBundle, `https://${currentHostname}${currentPath}`);
      if (bundleUrl.protocol === "https:" && bundleUrl.hostname === currentHostname) {
        const bundle = await pinnedRequest(currentHostname, `${bundleUrl.pathname}${bundleUrl.search}`, "GET", 65_536);
        reactVersion = bundle.body.match(/\bversion\s*=\s*[`"'](\d+(?:\.\d+){1,3})[`"']/i)?.[1];
      }
    } catch { /* A blocked optional asset must not fail the HTTP posture scan. */ }
  }
  const technologies = [headers.server && `Server: ${headers.server}`, headers["x-powered-by"] && `Powered by: ${headers["x-powered-by"]}`, generator && `Generator: ${generator}`,
    /wp-content|wp-includes/i.test(response.body) && "WordPress", /\/_next\//i.test(response.body) && "Next.js", /Drupal/i.test(response.body) && "Drupal",
    (reactBundle || /react-dom|jsx-runtime|\bReact\b/i.test(response.body)) && (reactVersion ? `React/${reactVersion}` : "React"),
    /<script[^>]+type=["']module["'][^>]+src=["']\/assets\/index-[^"']+\.js/i.test(response.body) && "Vite",
    /(?:src|href)=["'][^"']*trpc[^"']*["']/i.test(response.body) && "tRPC",
    /PHPSESSID/i.test(String(headers["set-cookie"] ?? "")) && "PHP", /laravel_session/i.test(String(headers["set-cookie"] ?? "")) && "Laravel"].filter(Boolean);
  const banners = technologies.filter((item): item is string => typeof item === "string");
  const detected = banners.map((banner) => {
    const match = banner.match(/\b(Apache|nginx|PHP|WordPress|Drupal|Next\.js)[/: ](\d+(?:\.\d+){0,3})/i);
    const generalMatch = match ?? banner.match(/\b(React|Vite)[/: ](\d+(?:\.\d+){1,3})/i);
    return generalMatch ? { name: generalMatch[1], version: generalMatch[2], source: banner } : { name: banner.replace(/^(Server|Powered by|Generator):\s*/i, ""), source: banner };
  });
  const technologyDetails = detected.filter((detail, index, all) => all.findIndex((candidate) => candidate.name.toLowerCase() === detail.name.toLowerCase() && candidate.version === detail.version) === index).map((detail) => ({
    ...detail,
    assessment: !detail.version ? "version_not_exposed" : detail.name.toLowerCase() === "react" && !/^19\.(?:0\.[0-3]|1\.[0-4]|2\.[0-3])$/.test(detail.version) ? "no_known_affected_version_match" : "version_requires_advisory_review",
    confidence: detail.version ? "high" : "medium",
  }));
  return { status: response.status, finalUrl: `https://${currentHostname}${currentPath}`, redirectChain, location: headers.location ?? null, securityHeaders, technologies: [...new Set(banners)], technologyDetails };
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
      lookup: pinnedLookup(address),
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
  let response: Response | undefined;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    response = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${hostname}`)}&output=json`, { signal: AbortSignal.timeout(10_000), headers: { Accept: "application/json", "User-Agent": "ASM-Control/1.0" } });
    if (response.ok || (response.status < 500 && response.status !== 429)) break;
    if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 500 * (attempt + 1)));
  }
  if (!response?.ok) throw new Error(`Certificate Transparency provider returned ${response?.status ?? "no response"}.`);
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
