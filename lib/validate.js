'use strict';

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const USERNAME = /^[A-Za-z0-9._-]{3,32}$/;

function parseIPv4(value) {
    if (typeof value !== 'string') return null;
    const ip = value.trim();
    return IPV4.test(ip) ? ip : null;
}

function parseBindHost(value) {
    if (value === undefined || value === null || String(value).trim() === '') return '0.0.0.0';
    const host = String(value).trim();
    if (host === '0.0.0.0' || host === '*') return '0.0.0.0';
    if (host === 'localhost') return '127.0.0.1';
    return parseIPv4(host);
}

function parsePort(value) {
    if (value === undefined || value === null) return null;
    const s = String(value).trim();
    if (!/^\d{1,5}$/.test(s)) return null;
    const n = Number(s);
    if (n < 1 || n > 65535) return null;
    return String(n);
}

function parseProtocol(value) {
    const s = String(value || '').trim().toLowerCase();
    return s === 'tcp' || s === 'udp' ? s : null;
}

function parseMethod(value) {
    const s = String(value || '').trim().toLowerCase();
    return s === 'socat' || s === 'iptables' ? s : null;
}

function parseUsername(value) {
    if (typeof value !== 'string') return null;
    const username = value.trim();
    return USERNAME.test(username) ? username : null;
}

function validateNewPassword(password, username) {
    if (typeof password !== 'string' || password.length < 10) {
        return 'Password must be at least 10 characters.';
    }
    if (password.length > 200) {
        return 'Password is too long.';
    }
    if (username && password.toLowerCase() === String(username).toLowerCase()) {
        return 'Password cannot match the username.';
    }
    return null;
}

module.exports = {
    parseIPv4,
    parseBindHost,
    parsePort,
    parseProtocol,
    parseMethod,
    parseUsername,
    validateNewPassword
};
