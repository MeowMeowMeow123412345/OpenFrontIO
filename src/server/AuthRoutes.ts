import { Request, Response, Router } from "express";
import { Magic } from "@magic-sdk/admin";
import { randomBytes, randomUUID } from "crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { getServerConfigFromServer } from "../core/configuration/ConfigLoader";
import { TokenPayloadSchema, UserMeResponse } from "../core/ApiSchemas";
import { verifyClientToken } from "./jwt";
import { uuidToBase64url } from "../core/Base64";

const config = getServerConfigFromServer();

const magicSecretKey = process.env.MAGIC_SECRET_KEY ?? "";
const refreshCookieName = "refresh_token";
const refreshTokens = new Map<
  string,
  {
    persistentId: string;
    email: string;
    expiresAt: number;
  }
>();
const usersByEmail = new Map<
  string,
  {
    email: string;
    persistentId: string;
    publicId: string;
  }
>();

const magic = new Magic(magicSecretKey);

let jwkPublic: unknown = null;
let privateKey: CryptoKey | undefined;

async function getJwkPublicKey() {
  if (jwkPublic) return jwkPublic;
  const { publicKey, privateKey: generatedPrivateKey } = await generateKeyPair("Ed25519");
  privateKey = generatedPrivateKey as CryptoKey;
  const exported = (await exportJWK(publicKey)) as Record<string, unknown>;
  exported.alg = "EdDSA";
  exported.use = "sig";
  exported.kid = "auth-key-1";
  jwkPublic = exported;
  return jwkPublic;
}

function parseOrigin(origin: string | undefined) {
  if (!origin) return null;
  try {
    return new URL(origin).origin;
  } catch {
    return null;
  }
}

function getAllowedOrigins(): Set<string> {
  const origins = new Set<string>();
  const env = process.env.CORS_ORIGINS;
  if (env) {
    env.split(",").forEach((value) => {
      const trimmed = value.trim();
      if (trimmed.length > 0) {
        origins.add(trimmed);
      }
    });
  }
  return origins;
}

function getAllowedOrigin(origin: string | undefined): string | null {
  const allowed = getAllowedOrigins();
  const parsed = parseOrigin(origin);
  if (!parsed) return null;
  if (allowed.has(parsed)) return parsed;
  return null;
}

function createPersistentId() {
  return uuidToBase64url(randomUUID());
}

function createPublicId() {
  return randomBytes(6).toString("base64url");
}

function createRefreshToken() {
  return randomBytes(32).toString("base64url");
}

function createUser(email: string) {
  const existing = usersByEmail.get(email);
  if (existing) return existing;

  const user = {
    email,
    persistentId: createPersistentId(),
    publicId: createPublicId(),
  };
  usersByEmail.set(email, user);
  return user;
}

function setRefreshCookie(res: Response, token: string) {
  const secure = process.env.NODE_ENV !== "development";
  res.cookie(refreshCookieName, token, {
    httpOnly: true,
    secure,
    sameSite: "none",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

async function createJwt(persistentId: string) {
  if (!privateKey) {
    await getJwkPublicKey();
  }
  if (!privateKey) {
    throw new Error("Auth private key not initialized");
  }

  const expiresInSeconds = 15 * 60;
  const jwt = await new SignJWT({})
    .setProtectedHeader({ alg: "EdDSA", kid: "auth-key-1" })
    .setSubject(persistentId)
    .setIssuer(config.jwtIssuer())
    .setAudience(config.jwtAudience())
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .setJti(randomBytes(8).toString("hex"))
    .sign(privateKey);

  return { jwt, expiresIn: expiresInSeconds };
}

async function verifyMagicToken(token: string) {
  if (!magicSecretKey) {
    throw new Error("MAGIC_SECRET_KEY is not set");
  }
  return magic.users.getMetadataByToken(token);
}

function sendCorsHeaders(req: Request, res: Response) {
  const origin = getAllowedOrigin(req.headers.origin);
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization",
    );
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
}

function createUserMeResponse(user: { email: string; persistentId: string; publicId: string }): UserMeResponse {
  return {
    user: {
      email: user.email,
    },
    player: {
      publicId: user.publicId,
      roles: [],
      flares: [],
      achievements: {
        singleplayerMap: [],
      },
    },
  };
}

export async function registerAuthRoutes(app: Router) {
  await getJwkPublicKey();

  app.use((req, res, next) => {
    sendCorsHeaders(req, res);
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  app.get("/.well-known/jwks.json", (_req, res) => {
    res.json({ keys: [jwkPublic] });
  });

  app.get("/users/@me", async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Authorization header required" });
    }
    const token = authHeader.substring("Bearer ".length);
    const result = await verifyClientToken(token, config);
    if (result.type !== "success") {
      return res.status(401).json({ error: result.message });
    }
    const user = Array.from(usersByEmail.values()).find(
      (entry) => entry.persistentId === result.persistentId,
    );
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(createUserMeResponse(user));
  });

  app.post("/auth/login/token", async (req, res) => {
    const loginToken = String(req.query["login-token"] ?? "");
    if (!loginToken) {
      return res.status(400).json({ error: "login-token parameter is required" });
    }

    try {
      const metadata = await verifyMagicToken(loginToken);
      if (!metadata.email) {
        return res.status(400).json({ error: "Magic token did not include an email" });
      }
      const user = createUser(metadata.email);
      const refreshToken = createRefreshToken();
      const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
      refreshTokens.set(refreshToken, {
        persistentId: user.persistentId,
        email: user.email,
        expiresAt,
      });
      setRefreshCookie(res, refreshToken);
      res.json({ email: user.email });
    } catch (error) {
      console.error("Failed to verify Magic token", error);
      return res.status(401).json({ error: "Invalid login token" });
    }
  });

  app.post("/auth/refresh", async (req, res) => {
    const token = req.cookies?.[refreshCookieName] as string | undefined;
    if (!token) {
      return res.status(401).json({ error: "Refresh token required" });
    }
    const record = refreshTokens.get(token);
    if (!record || record.expiresAt < Date.now()) {
      refreshTokens.delete(token);
      return res.status(401).json({ error: "Refresh token invalid or expired" });
    }

    const user = Array.from(usersByEmail.values()).find(
      (entry) => entry.persistentId === record.persistentId,
    );
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const newRefreshToken = createRefreshToken();
    const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
    refreshTokens.delete(token);
    refreshTokens.set(newRefreshToken, {
      persistentId: user.persistentId,
      email: user.email,
      expiresAt,
    });
    setRefreshCookie(res, newRefreshToken);

    const jwt = await createJwt(user.persistentId);
    res.json(jwt);
  });

  app.post("/auth/logout", (req, res) => {
    const token = req.cookies?.[refreshCookieName] as string | undefined;
    if (token) {
      refreshTokens.delete(token);
    }
    res.clearCookie(refreshCookieName, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== "development",
      sameSite: "none",
    });
    res.json({ success: true });
  });
}
