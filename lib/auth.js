'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const OTPAuth = require('otpauth');
const QRCode = require('qrcode');

const DATA_DIR = path.join(__dirname, '..', 'data');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const BCRYPT_ROUNDS = 12;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;
const ISSUER = 'Port Forward';

let cache = null;
let dummyHash = null;

function ensureDir() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { mode: 0o700 });
    }
}

function exists() {
    return fs.existsSync(AUTH_FILE);
}

function load() {
    if (cache) return cache;
    if (!exists()) return null;
    cache = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    return cache;
}

function save(data) {
    ensureDir();
    cache = data;
    const tmp = `${AUTH_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, AUTH_FILE);
    try { fs.chmodSync(AUTH_FILE, 0o600); } catch (_) { /* ignore */ }
}

function bootstrap({ username, password, sessionSecret }) {
    const data = {
        username,
        passwordHash: bcrypt.hashSync(password, BCRYPT_ROUNDS),
        totpEnabled: false,
        totpSecret: null,
        totpPendingSecret: null,
        backupCodeHashes: [],
        sessionSecret: sessionSecret || crypto.randomBytes(48).toString('hex'),
        failedAttempts: 0,
        lockedUntil: 0,
        mustChangePassword: true,
        createdAt: new Date().toISOString(),
        passwordUpdatedAt: new Date().toISOString(),
        lastLoginAt: null,
        lastLoginIp: null
    };
    save(data);
    return data;
}

function getDummyHash() {
    if (!dummyHash) {
        dummyHash = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_ROUNDS);
    }
    return dummyHash;
}

function safeEqual(a, b) {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) {
        crypto.timingSafeEqual(ba, ba);
        return false;
    }
    return crypto.timingSafeEqual(ba, bb);
}

function isLocked() {
    const a = load();
    if (!a) return false;
    return Date.now() < (a.lockedUntil || 0);
}

function lockRemainingMs() {
    const a = load();
    return Math.max(0, (a.lockedUntil || 0) - Date.now());
}

async function verifyPassword(username, password) {
    const a = load();
    const userOk = a && safeEqual(a.username, String(username || ''));
    const hash = userOk ? a.passwordHash : getDummyHash();
    const passOk = await bcrypt.compare(String(password || ''), hash);
    return Boolean(userOk && passOk);
}

function recordFailure() {
    const a = load();
    if (!a) return { locked: false, remainingMs: 0 };
    a.failedAttempts = (a.failedAttempts || 0) + 1;
    if (a.failedAttempts >= MAX_ATTEMPTS) {
        a.lockedUntil = Date.now() + LOCK_MS;
        a.failedAttempts = 0;
    }
    save(a);
    const remainingMs = Math.max(0, (a.lockedUntil || 0) - Date.now());
    return { locked: remainingMs > 0, remainingMs };
}

function recordSuccess(ip) {
    const a = load();
    a.failedAttempts = 0;
    a.lockedUntil = 0;
    a.lastLoginAt = new Date().toISOString();
    a.lastLoginIp = ip || null;
    save(a);
}

function getPublic() {
    const a = load();
    if (!a) return null;
    return {
        username: a.username,
        totpEnabled: !!a.totpEnabled,
        hasPendingTotp: !!a.totpPendingSecret,
        backupCodesRemaining: (a.backupCodeHashes || []).length,
        mustChangePassword: !!a.mustChangePassword,
        lastLoginAt: a.lastLoginAt,
        lastLoginIp: a.lastLoginIp,
        passwordUpdatedAt: a.passwordUpdatedAt,
        createdAt: a.createdAt
    };
}

function getSessionSecret() {
    return load()?.sessionSecret;
}

function mustChangePassword() {
    return !!load()?.mustChangePassword;
}

function isTotpEnabled() {
    return !!load()?.totpEnabled;
}

async function changePassword(current, next) {
    const a = load();
    const ok = await bcrypt.compare(String(current || ''), a.passwordHash);
    if (!ok) return { ok: false, error: 'Current password is incorrect.' };
    a.passwordHash = await bcrypt.hash(next, BCRYPT_ROUNDS);
    a.passwordUpdatedAt = new Date().toISOString();
    a.mustChangePassword = false;
    save(a);
    return { ok: true };
}

async function changeUsername(currentPassword, nextUsername) {
    const a = load();
    const ok = await bcrypt.compare(String(currentPassword || ''), a.passwordHash);
    if (!ok) return { ok: false, error: 'Current password is incorrect.' };
    a.username = nextUsername;
    save(a);
    return { ok: true };
}

function makeTotp(secretBase32, username) {
    return new OTPAuth.TOTP({
        issuer: ISSUER,
        label: username,
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: OTPAuth.Secret.fromBase32(secretBase32)
    });
}

function beginTotpSetup() {
    const a = load();
    const secret = new OTPAuth.Secret({ size: 20 });
    a.totpPendingSecret = secret.base32;
    save(a);
    const totp = makeTotp(secret.base32, a.username);
    return { secret: secret.base32, otpauth: totp.toString() };
}

function getPendingSetup() {
    const a = load();
    if (!a?.totpPendingSecret) return null;
    const totp = makeTotp(a.totpPendingSecret, a.username);
    return { secret: a.totpPendingSecret, otpauth: totp.toString() };
}

async function qrDataUrl(otpauth) {
    return QRCode.toDataURL(otpauth, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 240,
        color: { dark: '#0a1018', light: '#ffffff' }
    });
}

function verifyTotpToken(token, secret) {
    const a = load();
    const sec = secret || a?.totpSecret;
    if (!sec) return false;
    const cleaned = String(token || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(cleaned)) return false;
    const totp = makeTotp(sec, a.username);
    return totp.validate({ token: cleaned, window: 1 }) !== null;
}

function generateBackupCodes(n = 10) {
    const codes = [];
    for (let i = 0; i < n; i++) {
        const hex = crypto.randomBytes(5).toString('hex').toUpperCase();
        codes.push(`${hex.slice(0, 5)}-${hex.slice(5)}`);
    }
    return codes;
}

function hashBackupCode(code) {
    const norm = String(code || '').replace(/[-\s]/g, '').toUpperCase();
    return crypto.createHash('sha256').update(norm).digest('hex');
}

function consumeBackupCode(code) {
    const a = load();
    const h = hashBackupCode(code);
    const hashes = a.backupCodeHashes || [];
    const idx = hashes.findIndex((x) => safeEqual(x, h));
    if (idx === -1) return false;
    hashes.splice(idx, 1);
    a.backupCodeHashes = hashes;
    save(a);
    return true;
}

function confirmTotp(token) {
    const a = load();
    if (!a.totpPendingSecret) return { ok: false, error: 'No authenticator setup is in progress.' };
    if (!verifyTotpToken(token, a.totpPendingSecret)) {
        return { ok: false, error: 'That code is not valid. Check the time on your device and try again.' };
    }
    const plainCodes = generateBackupCodes(10);
    a.totpSecret = a.totpPendingSecret;
    a.totpPendingSecret = null;
    a.totpEnabled = true;
    a.backupCodeHashes = plainCodes.map(hashBackupCode);
    save(a);
    return { ok: true, backupCodes: plainCodes };
}

function cancelTotpSetup() {
    const a = load();
    a.totpPendingSecret = null;
    save(a);
}

async function disableTotp(password, token) {
    const a = load();
    const passOk = await bcrypt.compare(String(password || ''), a.passwordHash);
    if (!passOk) return { ok: false, error: 'Current password is incorrect.' };
    const totpOk = verifyTotpToken(token, a.totpSecret);
    const backupHash = hashBackupCode(token);
    const backupIdx = (a.backupCodeHashes || []).findIndex((x) => safeEqual(x, backupHash));
    if (!totpOk && backupIdx === -1) {
        return { ok: false, error: 'Enter a valid authenticator code or backup code.' };
    }
    a.totpEnabled = false;
    a.totpSecret = null;
    a.totpPendingSecret = null;
    a.backupCodeHashes = [];
    save(a);
    return { ok: true };
}

async function regenerateBackupCodes(password, token) {
    const a = load();
    const passOk = await bcrypt.compare(String(password || ''), a.passwordHash);
    if (!passOk) return { ok: false, error: 'Current password is incorrect.' };
    if (!verifyTotpToken(token, a.totpSecret)) {
        return { ok: false, error: 'That authenticator code is not valid.' };
    }
    const plainCodes = generateBackupCodes(10);
    a.backupCodeHashes = plainCodes.map(hashBackupCode);
    save(a);
    return { ok: true, backupCodes: plainCodes };
}

function verifyLoginSecondFactor(token) {
    if (verifyTotpToken(token)) return { ok: true, usedBackup: false };
    if (consumeBackupCode(token)) return { ok: true, usedBackup: true };
    return { ok: false };
}

module.exports = {
    exists,
    bootstrap,
    isLocked,
    lockRemainingMs,
    verifyPassword,
    recordFailure,
    recordSuccess,
    getPublic,
    getSessionSecret,
    mustChangePassword,
    isTotpEnabled,
    changePassword,
    changeUsername,
    beginTotpSetup,
    getPendingSetup,
    qrDataUrl,
    confirmTotp,
    cancelTotpSetup,
    disableTotp,
    regenerateBackupCodes,
    verifyLoginSecondFactor,
    safeEqual
};
