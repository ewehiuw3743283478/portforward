'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const fs = require('fs');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');

const auth = require('./lib/auth');
const firewall = require('./lib/firewall');
const updater = require('./lib/update');
const { listInterfaces, ipv4Of, parseIface } = require('./lib/net');
const {
    parseIPv4,
    parseBindHost,
    parsePort,
    parseProtocol,
    parseMethod,
    parseUsername,
    validateNewPassword
} = require('./lib/validate');

const PORTS_FILE = path.join(__dirname, 'ports.json');

if (!auth.exists()) {
    const missing = ['PORT', 'AUTH_USER', 'AUTH_PASS', 'SERVER_PUBLIC_IP'].filter((key) => !process.env[key]);
    if (missing.length) {
        console.error(`Missing required environment variables: ${missing.join(', ')}`);
        console.error('Copy .env.example to .env in the app directory, or run: sudo ./scripts/install-service.sh');
        process.exit(1);
    }
    const username = parseUsername(process.env.AUTH_USER);
    if (!username) {
        console.error('AUTH_USER must be 3–32 characters: letters, numbers, dot, underscore, or hyphen.');
        process.exit(1);
    }
    if (String(process.env.AUTH_PASS).length < 8) {
        console.error('AUTH_PASS must be at least 8 characters. It is only used once to create the hashed login.');
        process.exit(1);
    }
} else {
    const missing = ['PORT', 'SERVER_PUBLIC_IP'].filter((key) => !process.env[key]);
    if (missing.length) {
        console.error(`Missing required environment variables: ${missing.join(', ')}`);
        console.error('Set them in .env next to app.js (the systemd unit uses that file).');
        process.exit(1);
    }
}

const SERVER_PUBLIC_IP = parseIPv4(process.env.SERVER_PUBLIC_IP);
if (!SERVER_PUBLIC_IP) {
    console.error('SERVER_PUBLIC_IP must be a valid IPv4 address.');
    process.exit(1);
}

const PORT = parsePort(process.env.PORT);
if (!PORT) {
    console.error('PORT must be an integer between 1 and 65535.');
    process.exit(1);
}

const BIND_HOST = parseBindHost(process.env.BIND_HOST);
if (!BIND_HOST) {
    console.error('BIND_HOST must be 0.0.0.0, localhost, or a valid IPv4 address.');
    process.exit(1);
}

if (!auth.exists()) {
    auth.bootstrap({
        username: parseUsername(process.env.AUTH_USER),
        password: process.env.AUTH_PASS,
        sessionSecret: process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex')
    });
    console.log('Created data/auth.json with a hashed password. Sign in, then set a new panel password.');
}

const app = express();
const cookieSecure = process.env.COOKIE_SECURE === 'true' || process.env.COOKIE_SECURE === '1';
if (process.env.TRUST_PROXY === 'true' || process.env.TRUST_PROXY === '1') {
    app.set('trust proxy', 1);
}

app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: false,
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:'],
            formAction: ["'self'"],
            frameAncestors: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            ...(cookieSecure ? { upgradeInsecureRequests: [] } : {})
        }
    },
    strictTransportSecurity: cookieSecure ? { maxAge: 15552000, includeSubDomains: false } : false,
    referrerPolicy: { policy: 'no-referrer' }
}));

app.use(session({
    name: 'pf.sid',
    secret: process.env.SESSION_SECRET || auth.getSessionSecret(),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: cookieSecure,
        maxAge: 8 * 60 * 60 * 1000
    }
}));

app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use((req, _res, next) => {
    if (!req.body || typeof req.body !== 'object') req.body = {};
    next();
});
app.use(express.static(path.join(__dirname, 'public'), {
    index: false,
    maxAge: '1h'
}));

app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    const profile = auth.getPublic();
    res.locals.csrfToken = req.session.csrfToken;
    res.locals.currentUser = req.session.user || null;
    res.locals.publicIp = SERVER_PUBLIC_IP;
    res.locals.appPort = PORT;
    res.locals.profile = profile;
    res.locals.flash = pullFlash(req);
    res.locals.freshBackupCodes = req.session.freshBackupCodes || null;
    next();
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    handler: (req, res) => {
        setFlash(req, 'error', 'Too many sign-in attempts from this address. Try again in 15 minutes.');
        res.redirect('/login');
    }
});

let portDB = {};
const killDB = {};

function setFlash(req, type, message) {
    req.session.flash = { type, message };
}

function pullFlash(req) {
    const flash = req.session.flash || null;
    delete req.session.flash;
    return flash;
}

function verifyCsrf(req, res, next) {
    const token = req.body && req.body._csrf;
    if (!token || !req.session.csrfToken || !auth.safeEqual(token, req.session.csrfToken)) {
        setFlash(req, 'error', 'Your session expired. Refresh and try again.');
        const dest = req.path.startsWith('/login') || !isAuthed(req)
            ? '/login'
            : req.path.startsWith('/security')
                ? '/security'
                : req.path.startsWith('/update')
                    ? '/update'
                    : '/';
        return res.status(403).redirect(dest);
    }
    next();
}

function isAuthed(req) {
    return Boolean(req.session && req.session.user && !req.session.pending2fa);
}

function requireAuth(req, res, next) {
    if (req.session && req.session.pending2fa) return res.redirect('/login/otp');
    if (isAuthed(req)) return next();
    return res.redirect('/login');
}

function requireFreshPassword(req, res, next) {
    if (auth.mustChangePassword()) {
        setFlash(req, 'warning', 'Set a new password before managing forwards. The .env value is only for first-time setup.');
        return res.redirect('/security');
    }
    next();
}

function clientIp(req) {
    return req.ip || req.socket.remoteAddress || '';
}

function regenerateSession(req, fill) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((err) => {
            if (err) return reject(err);
            req.session.csrfToken = crypto.randomBytes(32).toString('hex');
            fill(req.session);
            resolve();
        });
    });
}

function ePort(port, protocol, method) {
    if (method === 'iptables') return `${port}_${protocol}_ipt`;
    return `${port}_${protocol}`;
}

function dPort(portProtocol) {
    const parts = portProtocol.split('_');
    if (parts.length === 3 && parts[2] === 'ipt') return [parts[0], parts[1], 'iptables'];
    return [parts[0], parts[1], 'socat'];
}

function decodePort(portProtocol, value) {
    const [port, protocol, method] = dPort(portProtocol);
    let ip;
    let toPort;
    let inIface = '*';
    let outIface = '';
    let firewallOn = false;
    if (typeof value === 'string') {
        [ip, toPort] = value.split(':');
    } else {
        ip = value.ip;
        toPort = value.toPort;
        inIface = value.inIface || '*';
        outIface = value.outIface || '';
        firewallOn = !!value.firewall;
    }
    return { port, protocol, ip, toPort, method, inIface, outIface, firewall: firewallOn };
}

function storeValue(entry) {
    return {
        ip: entry.ip,
        toPort: entry.toPort,
        inIface: entry.inIface || '*',
        outIface: entry.outIface || '',
        firewall: !!entry.firewall
    };
}

function listenAddress(entry) {
    if (entry.inIface && entry.inIface !== '*') {
        return ipv4Of(entry.inIface) || SERVER_PUBLIC_IP;
    }
    return SERVER_PUBLIC_IP;
}

function resolveSocat() {
    const candidates = ['/usr/bin/socat', '/bin/socat', '/usr/local/bin/socat'];
    for (const candidate of candidates) {
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return candidate;
        } catch (_) { /* try next */ }
    }
    try {
        const found = execFileSync('sh', ['-c', 'command -v socat'], {
            encoding: 'utf8',
            timeout: 3000,
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
        return found || null;
    } catch (_) {
        return null;
    }
}

const SOCAT_BIN = resolveSocat();
if (SOCAT_BIN) console.log(`Using socat at ${SOCAT_BIN}`);
else console.warn('socat not found on PATH; socat forwards will fail until it is installed');

function startWatcher(entry) {
    if (!SOCAT_BIN) {
        throw new Error('socat is not installed. Install the socat package, or use the iptables method.');
    }
    const protocol = entry.protocol;
    const socatProto = protocol === 'tcp' ? 'TCP' : 'UDP';
    let listen = `${socatProto}-LISTEN:${entry.port},reuseaddr,fork`;
    if (entry.inIface && entry.inIface !== '*') {
        const bindIp = ipv4Of(entry.inIface) || '0.0.0.0';
        listen += `,bind=${bindIp},so-bindtodevice=${entry.inIface}`;
    } else {
        listen += ',bind=0.0.0.0';
    }
    let dest = `${socatProto}:${entry.ip}:${entry.toPort},reuseaddr`;
    if (entry.outIface) {
        dest += `,so-bindtodevice=${entry.outIface}`;
        const outIp = ipv4Of(entry.outIface);
        if (outIp) dest += `,bind=${outIp}`;
    }
    const key = ePort(entry.port, protocol, 'socat');
    const socat = spawn(SOCAT_BIN, [listen, dest], { stdio: ['ignore', 'pipe', 'pipe'] });
    socat.on('error', (err) => {
        console.error(`socat error for ${entry.port}/${protocol}: ${err.code || ''} ${err.message}`);
        delete killDB[key];
    });
    if (socat.pid) killDB[key] = socat.pid;
    if (socat.stdout) socat.stdout.on('data', (data) => console.log(`stdout ${socat.pid}: ${data}`));
    if (socat.stderr) socat.stderr.on('data', (data) => console.log(`stderr ${socat.pid}: ${data}`));
    socat.on('exit', (code, signal) => {
        if (killDB[key] === socat.pid) delete killDB[key];
        if (code) console.error(`socat for ${entry.port}/${protocol} exited ${code}${signal ? `/${signal}` : ''}`);
    });
    console.log(`Started socat watcher for ${socatProto} port ${entry.port} on ${entry.inIface || '*'} with pid ${socat.pid}`);
}

function stopWatcher(port, protocol) {
    const pid = killDB[ePort(port, protocol, 'socat')];
    if (!pid) return;
    try { process.kill(pid, 'SIGKILL'); } catch (_) { /* already gone */ }
    delete killDB[ePort(port, protocol, 'socat')];
    console.log(`Stopped socat watcher for ${port} with pid ${pid}`);
}

function enableIpForward() {
    try { fs.writeFileSync('/proc/sys/net/ipv4/ip_forward', '1'); } catch (err) {
        console.error(`Could not enable ip_forward: ${err.message}`);
    }
}

function natCommands(action, entry) {
    const dest = `${entry.ip}:${entry.toPort}`;
    const pre = ['-t', 'nat', action, 'PREROUTING', '-p', entry.protocol];
    if (entry.inIface && entry.inIface !== '*') pre.push('-i', entry.inIface);
    else pre.push('-d', SERVER_PUBLIC_IP);
    pre.push('--dport', String(entry.port), '-j', 'DNAT', '--to-destination', dest);

    const commands = [
        pre,
        [
            '-t', 'nat', action, 'OUTPUT', '-p', entry.protocol, '-d', SERVER_PUBLIC_IP,
            '--dport', String(entry.port), '-j', 'DNAT', '--to-destination', dest
        ]
    ];
    if (entry.outIface) {
        commands.push([
            '-t', 'nat', action, 'POSTROUTING', '-o', entry.outIface, '-p', entry.protocol,
            '-d', entry.ip, '--dport', String(entry.toPort), '-j', 'MASQUERADE'
        ]);
    }
    return commands;
}

function iptablesNat(action, entry) {
    for (const args of natCommands(action, entry)) {
        execFileSync('iptables', args, { timeout: 5000 });
    }
}

function iptablesAddForward(entry) {
    try {
        enableIpForward();
        iptablesNat('-A', entry);
        console.log(`Added iptables forward ${entry.protocol} ${entry.port} => ${entry.ip}:${entry.toPort} in=${entry.inIface} out=${entry.outIface || 'auto'}`);
    } catch (e) {
        console.error(e.stderr?.toString() || e.message);
        throw new Error('iptables add failed');
    }
}

function iptablesRemoveForward(entry) {
    try {
        iptablesNat('-D', entry);
        console.log(`Removed iptables forward ${entry.protocol} ${entry.port} => ${entry.ip}:${entry.toPort}`);
    } catch (e) {
        console.error(e.stderr?.toString() || e.message);
    }
}

function listEntries() {
    const entries = [];
    for (const key of Object.keys(portDB)) {
        const entry = decodePort(key, portDB[key]);
        entry.listenIp = listenAddress(entry);
        entries.push(entry);
    }
    entries.sort((a, b) => Number(a.port) - Number(b.port) || a.protocol.localeCompare(b.protocol) || a.method.localeCompare(b.method));
    return entries;
}

function applyForward(entry) {
    if (entry.method === 'iptables') iptablesAddForward(entry);
    else startWatcher(entry);
    if (!entry.firewall) return { firewall: false };
    const fw = firewall.open(entry);
    if (fw.ufwError) console.error(`UFW did not open the port: ${fw.ufwError}`);
    if (fw.iptablesError) console.error(`iptables hole failed: ${fw.iptablesError}`);
    return fw;
}

function firewallSummary(fw) {
    if (!fw || fw.firewall === false) return 'firewall unchanged';
    const bits = [];
    if (fw.iptables) bits.push('iptables');
    if (fw.ufw && fw.ufwActive) bits.push('UFW');
    else if (fw.ufw && !fw.ufwActive) bits.push('UFW (inactive, rule saved)');
    if (fw.ufwError) bits.push(`UFW failed: ${fw.ufwError.split('\n')[0]}`);
    if (fw.iptablesError) bits.push(`iptables failed: ${fw.iptablesError.split('\n')[0]}`);
    if (fw.ufwWarning) bits.push(fw.ufwWarning);
    return bits.length ? bits.join('; ') : 'firewall attempted';
}

function withdrawForward(entry) {
    if (entry.firewall) {
        try { firewall.close(entry); } catch (err) { console.error(err); }
    }
    if (entry.method === 'iptables') iptablesRemoveForward(entry);
    else stopWatcher(entry.port, entry.protocol);
}

function stopAllForwards() {
    for (const key of Object.keys(portDB)) {
        try {
            withdrawForward(decodePort(key, portDB[key]));
        } catch (err) {
            console.error(`Could not stop ${key}: ${err.message || err}`);
        }
    }
    try { firewall.flush(); } catch (err) { console.error(err); }
}

function startAllForwards() {
    try {
        firewall.ensure();
    } catch (err) {
        console.error(`Firewall setup failed: ${err.message || err}`);
    }
    for (const key of Object.keys(portDB)) {
        try {
            applyForward(decodePort(key, portDB[key]));
        } catch (err) {
            console.error(`Could not restore ${key}: ${err.message || err}`);
        }
    }
}

function syncPortDB() {
    if (!fs.existsSync(PORTS_FILE)) {
        fs.writeFileSync(PORTS_FILE, '{}\n');
    }
    try {
        portDB = JSON.parse(fs.readFileSync(PORTS_FILE, 'utf8'));
    } catch (err) {
        console.error(`Could not read ports.json: ${err.message}`);
        portDB = {};
        return;
    }
    try { stopAllForwards(); } catch (err) { console.error(err); }
    try { startAllForwards(); } catch (err) { console.error(err); }
}

function savePortDB() {
    fs.writeFileSync(PORTS_FILE, `${JSON.stringify(portDB, null, 4)}\n`);
}

syncPortDB();

app.get('/login', (req, res) => {
    if (isAuthed(req)) return res.redirect('/');
    if (req.session.pending2fa) return res.redirect('/login/otp');
    res.render('login', { title: 'Sign in' });
});

app.post('/login', loginLimiter, verifyCsrf, async (req, res) => {
    try {
        if (auth.isLocked()) {
            const mins = Math.max(1, Math.ceil(auth.lockRemainingMs() / 60000));
            setFlash(req, 'error', `Too many failed attempts. Try again in ${mins} minute${mins === 1 ? '' : 's'}.`);
            return res.redirect('/login');
        }
        const username = String(req.body.username || '');
        const password = String(req.body.password || '');
        const ok = await auth.verifyPassword(username, password);
        if (!ok) {
            const fail = auth.recordFailure();
            if (fail.locked) {
                setFlash(req, 'error', 'Too many failed attempts. Try again in 15 minutes.');
            } else {
                setFlash(req, 'error', 'Invalid username or password.');
            }
            return res.redirect('/login');
        }
        if (auth.isTotpEnabled()) {
            await regenerateSession(req, (s) => {
                s.pending2fa = true;
                s.pendingUser = auth.getPublic().username;
                s.otpAttempts = 0;
            });
            return res.redirect('/login/otp');
        }
        auth.recordSuccess(clientIp(req));
        await regenerateSession(req, (s) => {
            s.user = auth.getPublic().username;
        });
        return res.redirect(auth.mustChangePassword() ? '/security' : '/');
    } catch (err) {
        console.error(err);
        setFlash(req, 'error', 'Could not sign in. Try again.');
        return res.redirect('/login');
    }
});

app.get('/login/otp', (req, res) => {
    if (isAuthed(req)) return res.redirect('/');
    if (!req.session.pending2fa) return res.redirect('/login');
    res.render('otp', { title: 'Authenticator code' });
});

app.post('/login/otp', loginLimiter, verifyCsrf, async (req, res) => {
    try {
        if (!req.session.pending2fa) return res.redirect('/login');
        if (auth.isLocked()) {
            req.session.destroy(() => {});
            setFlash(req, 'error', 'Too many failed attempts. Try again in 15 minutes.');
            return res.redirect('/login');
        }
        const token = String(req.body.otp || '');
        const result = auth.verifyLoginSecondFactor(token);
        if (!result.ok) {
            req.session.otpAttempts = (req.session.otpAttempts || 0) + 1;
            const fail = auth.recordFailure();
            if (fail.locked || req.session.otpAttempts >= 5) {
                delete req.session.pending2fa;
                delete req.session.pendingUser;
                req.session.otpAttempts = 0;
                setFlash(req, 'error', 'Too many failed attempts. Sign in again.');
                return res.redirect('/login');
            }
            setFlash(req, 'error', 'That authenticator or backup code is not valid.');
            return res.redirect('/login/otp');
        }
        const username = req.session.pendingUser;
        auth.recordSuccess(clientIp(req));
        await regenerateSession(req, (s) => {
            s.user = username;
        });
        if (result.usedBackup) {
            setFlash(req, 'warning', `Signed in with a backup code. ${auth.getPublic().backupCodesRemaining} remaining.`);
        }
        return res.redirect(auth.mustChangePassword() ? '/security' : '/');
    } catch (err) {
        console.error(err);
        setFlash(req, 'error', 'Could not verify the code. Try again.');
        return res.redirect('/login/otp');
    }
});

app.post('/logout', verifyCsrf, (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.get('/', requireAuth, requireFreshPassword, (req, res) => {
    res.render('index', {
        title: 'Forwards',
        entries: listEntries(),
        totpEnabled: auth.isTotpEnabled(),
        ifaces: listInterfaces(),
        fwStatus: firewall.status()
    });
});

app.post('/add', requireAuth, requireFreshPassword, verifyCsrf, (req, res) => {
    const ip = parseIPv4(req.body.ip);
    const port = parsePort(req.body.port);
    const toPort = parsePort(req.body.toPort);
    const protocol = parseProtocol(req.body.protocol);
    const method = parseMethod(req.body.method || 'socat');
    const inIface = parseIface(req.body.inIface, { allowAll: true });
    const outIface = parseIface(req.body.outIface, { allowEmpty: true });
    const firewallOn = req.body.firewall === '1' || req.body.firewall === 'on';

    if (!ip) {
        setFlash(req, 'error', 'Enter a valid IPv4 destination address.');
        return res.redirect('/');
    }
    if (!port || !toPort) {
        setFlash(req, 'error', 'Ports must be integers from 1 to 65535.');
        return res.redirect('/');
    }
    if (!protocol) {
        setFlash(req, 'error', 'Choose TCP or UDP.');
        return res.redirect('/');
    }
    if (!method) {
        setFlash(req, 'error', 'Choose socat or iptables.');
        return res.redirect('/');
    }
    if (inIface === null) {
        setFlash(req, 'error', 'Choose a valid inbound interface, or All.');
        return res.redirect('/');
    }
    if (outIface === null) {
        setFlash(req, 'error', 'Choose a valid outbound interface, or Auto.');
        return res.redirect('/');
    }
    if (port === PORT) {
        setFlash(req, 'error', `Port ${PORT} is used by this panel. Pick a different listen port.`);
        return res.redirect('/');
    }

    const key = ePort(port, protocol, method);
    if (portDB[key]) {
        setFlash(req, 'error', 'That listen port, protocol, and method is already forwarded.');
        return res.redirect('/');
    }

    const entry = { port, protocol, ip, toPort, method, inIface, outIface, firewall: firewallOn };
    let fwResult = { firewall: false };

    try {
        if (method === 'iptables') {
            try { iptablesRemoveForward(entry); } catch (_) { /* ignore leftover NAT */ }
        }
        fwResult = applyForward(entry);
    } catch (e) {
        try { withdrawForward(entry); } catch (_) { /* ignore rollback */ }
        setFlash(req, 'error', e.message || 'Could not add the forward.');
        return res.redirect('/');
    }

    portDB[key] = storeValue(entry);
    savePortDB();
    const inLabel = inIface === '*' ? 'all NICs' : inIface;
    const outLabel = outIface || 'auto';
    const fwLabel = firewallSummary(fwResult);
    const flashType = fwResult && (fwResult.ufwError || fwResult.iptablesError || fwResult.ufwWarning) ? 'warning' : 'success';
    setFlash(req, flashType, `Forwarding ${listenAddress(entry)}:${port}/${protocol} → ${ip}:${toPort} (${method}, in ${inLabel}, out ${outLabel}, ${fwLabel}).`);
    res.redirect('/');
});

app.post('/remove', requireAuth, requireFreshPassword, verifyCsrf, (req, res) => {
    const port = parsePort(req.body.port);
    const protocol = parseProtocol(req.body.protocol);
    const method = parseMethod(req.body.method || 'socat');
    if (!port || !protocol || !method) {
        setFlash(req, 'error', 'Invalid forward.');
        return res.redirect('/');
    }
    const key = ePort(port, protocol, method);
    const stored = portDB[key];
    if (!stored) {
        setFlash(req, 'error', 'That forward is not in the list.');
        return res.redirect('/');
    }
    const entry = decodePort(key, stored);
    withdrawForward(entry);
    delete portDB[key];
    savePortDB();
    setFlash(req, 'success', `Removed ${port}/${protocol} (${method}).`);
    res.redirect('/');
});

app.get('/security', requireAuth, async (req, res) => {
    let totpSetup = null;
    const pending = auth.getPendingSetup();
    if (pending) {
        totpSetup = {
            secret: pending.secret,
            qr: await auth.qrDataUrl(pending.otpauth)
        };
    }
    res.render('security', {
        title: 'Security',
        totpSetup,
        mustChangePassword: auth.mustChangePassword()
    });
});

app.post('/security/username', requireAuth, verifyCsrf, async (req, res) => {
    const nextUsername = parseUsername(req.body.username);
    if (!nextUsername) {
        setFlash(req, 'error', 'Username must be 3–32 characters: letters, numbers, dot, underscore, or hyphen.');
        return res.redirect('/security');
    }
    const result = await auth.changeUsername(req.body.currentPassword, nextUsername);
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/security');
    }
    req.session.user = nextUsername;
    setFlash(req, 'success', 'Username updated.');
    res.redirect('/security');
});

app.post('/security/password', requireAuth, verifyCsrf, async (req, res) => {
    const next = String(req.body.newPassword || '');
    const confirm = String(req.body.confirmPassword || '');
    if (next !== confirm) {
        setFlash(req, 'error', 'New password and confirmation do not match.');
        return res.redirect('/security');
    }
    const problem = validateNewPassword(next, req.session.user);
    if (problem) {
        setFlash(req, 'error', problem);
        return res.redirect('/security');
    }
    const result = await auth.changePassword(req.body.currentPassword, next);
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/security');
    }
    setFlash(req, 'success', 'Password updated. Use it the next time you sign in.');
    res.redirect('/security');
});

app.post('/security/totp/start', requireAuth, verifyCsrf, (req, res) => {
    if (auth.isTotpEnabled()) {
        setFlash(req, 'error', 'Authenticator is already enabled.');
        return res.redirect('/security');
    }
    auth.beginTotpSetup();
    res.redirect('/security');
});

app.post('/security/totp/cancel', requireAuth, verifyCsrf, (req, res) => {
    auth.cancelTotpSetup();
    setFlash(req, 'info', 'Authenticator setup cancelled.');
    res.redirect('/security');
});

app.post('/security/totp/enable', requireAuth, verifyCsrf, async (req, res) => {
    const result = auth.confirmTotp(req.body.otp);
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/security');
    }
    req.session.freshBackupCodes = result.backupCodes;
    setFlash(req, 'success', 'Authenticator app enabled. Save the backup codes before leaving this page.');
    res.redirect('/security');
});

app.post('/security/totp/disable', requireAuth, verifyCsrf, async (req, res) => {
    const result = await auth.disableTotp(req.body.currentPassword, req.body.otp);
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/security');
    }
    delete req.session.freshBackupCodes;
    setFlash(req, 'success', 'Authenticator app disabled.');
    res.redirect('/security');
});

app.post('/security/backup-codes', requireAuth, verifyCsrf, async (req, res) => {
    const result = await auth.regenerateBackupCodes(req.body.currentPassword, req.body.otp);
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/security');
    }
    req.session.freshBackupCodes = result.backupCodes;
    setFlash(req, 'warning', 'Previous backup codes no longer work. Save the new set.');
    res.redirect('/security');
});

app.post('/security/backup-codes/ack', requireAuth, verifyCsrf, (req, res) => {
    delete req.session.freshBackupCodes;
    res.redirect('/security');
});

app.get('/update', requireAuth, requireFreshPassword, (req, res) => {
    res.render('update', {
        title: 'Update',
        update: updater.status()
    });
});

app.post('/update/check', requireAuth, requireFreshPassword, verifyCsrf, (req, res) => {
    const result = updater.fetchRemote();
    if (!result.ok) {
        setFlash(req, 'error', result.error);
        return res.redirect('/update');
    }
    const behind = result.status.behind;
    if (behind === 0) setFlash(req, 'success', 'Already on the latest commit from origin.');
    else if (behind > 0) setFlash(req, 'info', `${behind} new commit${behind === 1 ? '' : 's'} on origin. Apply the update when you are ready.`);
    else setFlash(req, 'info', 'Fetched origin. Compare the commits below.');
    res.redirect('/update');
});

app.post('/update/apply', requireAuth, requireFreshPassword, verifyCsrf, async (req, res) => {
    const username = auth.getPublic().username;
    const ok = await auth.verifyPassword(username, req.body.currentPassword);
    if (!ok) {
        setFlash(req, 'error', 'Current password is incorrect.');
        return res.redirect('/update');
    }
    try {
        updater.startApply();
        setFlash(req, 'warning', 'Update started. The panel will restart; refresh this page in a few seconds.');
    } catch (err) {
        setFlash(req, 'error', err.message || 'Could not start the update.');
    }
    res.redirect('/update');
});

app.use((req, res) => {
    if (req.path === '/favicon.ico' || !req.accepts('html')) {
        return res.status(404).end();
    }
    if (req.path.startsWith('/login') || !isAuthed(req)) {
        return res.status(404).redirect('/login');
    }
    setFlash(req, 'error', 'Page not found.');
    res.redirect('/');
});

app.use((err, req, res, _next) => {
    console.error(err);
    if (req.session) setFlash(req, 'error', 'Something went wrong.');
    res.redirect(isAuthed(req) ? '/' : '/login');
});

const server = app.listen(Number(PORT), BIND_HOST, () => {
    console.log(`Port Forward panel listening on ${BIND_HOST}:${PORT}`);
});

server.on('error', (err) => {
    console.error(`Cannot listen on ${BIND_HOST}:${PORT}: ${err.message}`);
    process.exit(1);
});

let shuttingDown = false;
function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Received ${signal}, stopping forwards`);
    try { stopAllForwards(); } catch (err) { console.error(err); }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 8000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
