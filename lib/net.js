'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const IFACE_RE = /^[A-Za-z][A-Za-z0-9:._-]{0,14}$/;

function ignoredName(name) {
    return name === 'lo'
        || name.startsWith('docker')
        || name.startsWith('br-')
        || name.startsWith('veth')
        || name.startsWith('virbr')
        || name.startsWith('dummy');
}

function ifaceExists(name) {
    return fs.existsSync(path.join('/sys/class/net', name));
}

function ipv4Of(name) {
    const addrs = os.networkInterfaces()[name];
    if (!addrs) return null;
    const found = addrs.find((a) => a && (a.family === 'IPv4' || a.family === 4) && !a.internal);
    return found ? found.address : null;
}

function listInterfaces() {
    const nics = os.networkInterfaces();
    const names = new Set([...Object.keys(nics)]);
    try {
        for (const name of fs.readdirSync('/sys/class/net')) names.add(name);
    } catch (_) { /* ignore */ }

    const result = [];
    for (const name of names) {
        if (ignoredName(name) || !IFACE_RE.test(name) || !ifaceExists(name)) continue;
        let state = 'unknown';
        try {
            state = fs.readFileSync(path.join('/sys/class/net', name, 'operstate'), 'utf8').trim();
        } catch (_) { /* ignore */ }
        result.push({
            name,
            ipv4: ipv4Of(name),
            state
        });
    }
    result.sort((a, b) => a.name.localeCompare(b.name));
    return result;
}

function parseIface(value, { allowAll = false, allowEmpty = false } = {}) {
    if (value === undefined || value === null) return allowEmpty ? '' : null;
    const name = String(value).trim();
    if (name === '' && allowEmpty) return '';
    if (allowAll && (name === '*' || name.toLowerCase() === 'all')) return '*';
    if (!IFACE_RE.test(name)) return null;
    if (!ifaceExists(name)) return null;
    return name;
}

module.exports = {
    listInterfaces,
    ipv4Of,
    parseIface,
    ifaceExists
};
