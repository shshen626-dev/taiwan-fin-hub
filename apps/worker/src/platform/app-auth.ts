import type { Env } from "./env";

const SESSION_COOKIE = "tfh_session";
const SESSION_VERSION = "v1";
const SESSION_DURATION_SECONDS = 30 * 24 * 60 * 60;

type AppAuthEnv = Pick<Env, "APP_AUTH_PASSWORD" | "APP_AUTH_SECRET">;

export function isAppPasswordAuthConfigured(
  env: AppAuthEnv,
): env is AppAuthEnv & {
  APP_AUTH_PASSWORD: string;
  APP_AUTH_SECRET: string;
} {
  return Boolean(env.APP_AUTH_PASSWORD && env.APP_AUTH_SECRET);
}

export async function passwordMatches(candidate: string, env: AppAuthEnv) {
  if (!isAppPasswordAuthConfigured(env)) return false;

  const [candidateDigest, expectedDigest] = await Promise.all([
    hmac(candidate, env.APP_AUTH_SECRET),
    hmac(env.APP_AUTH_PASSWORD, env.APP_AUTH_SECRET),
  ]);
  return timingSafeEqual(candidateDigest, expectedDigest);
}

export async function createSessionCookie(env: AppAuthEnv, now = Date.now()) {
  if (!isAppPasswordAuthConfigured(env)) {
    throw new Error("Application password authentication is not configured.");
  }

  const expiresAt = Math.floor(now / 1000) + SESSION_DURATION_SECONDS;
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const unsigned = [
    SESSION_VERSION,
    String(expiresAt),
    encodeBase64Url(nonceBytes),
  ].join(".");
  const signature = encodeBase64Url(await hmac(unsigned, env.APP_AUTH_SECRET));
  const value = `${unsigned}.${signature}`;

  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${SESSION_DURATION_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

export async function verifyAppSession(
  request: Request,
  env: AppAuthEnv,
  now = Date.now(),
) {
  if (!isAppPasswordAuthConfigured(env)) return false;

  const token = cookieValue(request.headers.get("Cookie"), SESSION_COOKIE);
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 4) return false;
  const [version, expiresAtValue, nonce, encodedSignature] = parts as [
    string,
    string,
    string,
    string,
  ];
  if (version !== SESSION_VERSION || !/^\d+$/.test(expiresAtValue))
    return false;
  if (!/^[A-Za-z0-9_-]{22}$/.test(nonce)) return false;

  const expiresAt = Number(expiresAtValue);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= Math.floor(now / 1000)) {
    return false;
  }

  let suppliedSignature: Uint8Array;
  try {
    suppliedSignature = decodeBase64Url(encodedSignature);
  } catch {
    return false;
  }
  const expectedSignature = await hmac(
    `${version}.${expiresAtValue}.${nonce}`,
    env.APP_AUTH_SECRET,
  );
  return timingSafeEqual(suppliedSignature, expectedSignature);
}

async function hmac(value: string, secret: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)),
  );
}

function timingSafeEqual(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function cookieValue(header: string | null, name: string) {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [candidateName, ...valueParts] = part.trim().split("=");
    if (candidateName === name) return valueParts.join("=");
  }
  return undefined;
}

function encodeBase64Url(value: Uint8Array) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
