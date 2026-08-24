'use strict';

const fs = require('fs');
const { execFileSync } = require('child_process');

const CHAIN = 'PORTFORWARD';
const COMMENT_PREFIX = 'pf';

function findBin(name) {
    const candidates = [
        `/usr/sbin/${name}`,
        `/sbin/${name}`,
        `/usr/bin/${name}`,
        `/bin/${name}`
    ];
    for (const candidate of candidates) {
        try {
            fs.accessSync(candidate, fs.constants.X_OK);
            return candidate;
        } catch (_) { /* try next */ }
    }
    try {
        const found = execFileSync('sh', ['-c', `command -v ${name} || true`], {
            encoding: 'utf8',
            timeout: 3000,
            env: {
                ...process.env,
                PATH: `${process.env.PATH || ''}:/usr/sbin:/sbin:/usr/bin:/bin`
            },
            stdio: ['ignore', 'pipe', 'pipe']
        }).trim();
        return found || null;
    } catch (_) {
        return null;
    }
}

const IPTABLES = findBin('iptables');
const UFW = findBin('ufw');

function run(bin, args, { ignore = false, timeout = 20000 } = {}) {
    try {
        return execFileSync(bin, args, {
            timeout,
            encoding: 'utf8',
            env: {
                ...process.env,
                PATH: `/usr/sbin:/sbin:/usr/bin:/bin:${process.env.PATH || ''}`
            },
            stdio: ['ignore', 'pipe', 'pipe']
        });
    } catch (err) {
        if (ignore) return (err.stdout || '').toString();
        const detail = [(err.stderr || '').toString(), (err.stdout || '').toString(), err.message]
            .map((s) => s.trim())
            .filter(Boolean)
            .join('\n');
        const wrapped = new Error(detail || `${bin} failed`);
        wrapped.cause = err;
        throw wrapped;
    }
}

function iptablesHas(args) {
    if (!IPTABLES) return false;
    try {
        execFileSync(IPTABLES, ['-C', ...args], {
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return true;
    } catch (_) {
        return false;
    }
}

function commentTag(kind, protocol, port) {
    return `${COMMENT_PREFIX}:${kind}:${protocol}:${port}`.slice(0, 255);
}

function ufwStatusText() {
    if (!UFW) return '';
    try {
        return run(UFW, ['status']);
    } catch (_) {
        return '';
    }
}

function ufwActive() {
    return /Status:\s*active/i.test(ufwStatusText());
}

function iptablesAvailable() {
    return Boolean(IPTABLES);
}

function status() {
    return {
        ufwInstalled: Boolean(UFW),
        ufwPath: UFW,
        ufwActive: Boolean(UFW) && ufwActive(),
        iptables: iptablesAvailable(),
        iptablesPath: IPTABLES
    };
}

function chainExists() {
    if (!IPTABLES) return false;
    try {
        execFileSync(IPTABLES, ['-n', '-L', CHAIN], {
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return true;
    } catch (_) {
        return false;
    }
}

function ensure() {
    if (!IPTABLES) return;
    if (!chainExists()) run(IPTABLES, ['-N', CHAIN], { ignore: true });
    if (!iptablesHas(['INPUT', '-j', CHAIN])) {
        run(IPTABLES, ['-I', 'INPUT', '1', '-j', CHAIN]);
    }
    if (!iptablesHas(['FORWARD', '-j', CHAIN])) {
        run(IPTABLES, ['-I', 'FORWARD', '1', '-j', CHAIN]);
    }
    const established = [CHAIN, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'];
    if (!iptablesHas(established)) {
        run(IPTABLES, ['-A', ...established]);
    }
}

function flush() {
    if (!chainExists()) return;
    run(IPTABLES, ['-F', CHAIN], { ignore: true });
    run(IPTABLES, ['-A', CHAIN, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], { ignore: true });
}

function inputSpec(entry) {
    const args = [];
    if (entry.inIface && entry.inIface !== '*') args.push('-i', entry.inIface);
    args.push(
        '-p', entry.protocol,
        '--dport', String(entry.port),
        '-m', 'comment', '--comment', commentTag('in', entry.protocol, entry.port),
        '-j', 'ACCEPT'
    );
    return args;
}

function forwardSpec(entry) {
    const args = [];
    if (entry.inIface && entry.inIface !== '*') args.push('-i', entry.inIface);
    if (entry.outIface) args.push('-o', entry.outIface);
    args.push(
        '-p', entry.protocol,
        '-d', entry.ip,
        '--dport', String(entry.toPort),
        '-m', 'comment', '--comment', commentTag('fwd', entry.protocol, entry.port),
        '-j', 'ACCEPT'
    );
    return args;
}

function applyRule(action, spec) {
    if (!IPTABLES) return;
    const args = [action, CHAIN, ...spec];
    if (action === '-A' && iptablesHas([CHAIN, ...spec])) return;
    run(IPTABLES, args, { ignore: action === '-D' });
}

function ufwInputArgs(entry, deleting) {
    const args = [];
    if (deleting) args.push('delete');
    args.push('allow');
    if (entry.inIface && entry.inIface !== '*') {
        args.push('in', 'on', entry.inIface, 'proto', entry.protocol, 'to', 'any', 'port', String(entry.port));
    } else {
        args.push(`${entry.port}/${entry.protocol}`);
    }
    if (!deleting) args.push('comment', `portforward-${entry.port}-${entry.protocol}`);
    return args;
}

function ufwRouteArgs(entry, deleting) {
    const args = ['route'];
    if (deleting) args.push('delete');
    args.push('allow');
    if (entry.inIface && entry.inIface !== '*') args.push('in', 'on', entry.inIface);
    if (entry.outIface) args.push('out', 'on', entry.outIface);
    args.push('proto', entry.protocol, 'to', entry.ip, 'port', String(entry.toPort));
    return args;
}

function ufwAdded() {
    if (!UFW) return '';
    try {
        return run(UFW, ['show', 'added']);
    } catch (_) {
        return '';
    }
}

function ufwHasInput(entry) {
    const added = ufwAdded();
    if (!added) return false;
    const portProto = `${entry.port}/${entry.protocol}`;
    if (entry.inIface && entry.inIface !== '*') {
        return added.includes(`in on ${entry.inIface}`) && added.includes(`port ${entry.port}`);
    }
    return added.includes(portProto) || added.includes(`port ${entry.port}`);
}

function open(entry) {
    const result = {
        ufw: false,
        ufwInstalled: Boolean(UFW),
        ufwActive: Boolean(UFW) && ufwActive(),
        iptables: false
    };
    try {
        ensure();
        applyRule('-A', inputSpec(entry));
        if (entry.method === 'iptables') applyRule('-A', forwardSpec(entry));
        result.iptables = true;
    } catch (err) {
        result.iptablesError = err.message;
        console.error(`iptables PORTFORWARD failed: ${err.message}`);
    }

    if (!UFW) {
        result.ufwError = 'ufw binary not found (looked in /usr/sbin/ufw).';
        return result;
    }

    try {
        const out = run(UFW, ufwInputArgs(entry, false));
        result.ufwOutput = (out || '').trim();
        if (entry.method === 'iptables') {
            run(UFW, ufwRouteArgs(entry, false));
        }
        // ufw rewrites filter tables; put our chain back in front.
        ensure();
        applyRule('-A', inputSpec(entry));
        if (entry.method === 'iptables') applyRule('-A', forwardSpec(entry));
        result.ufw = ufwHasInput(entry) || /Rules updated/i.test(result.ufwOutput || '');
        result.ufwActive = ufwActive();
        if (result.ufw && !result.ufwActive) {
            result.ufwWarning = 'UFW rule saved, but UFW is inactive so it is not enforcing until you run: ufw enable';
        }
    } catch (err) {
        result.ufwError = err.message;
        console.error(`ufw allow failed: ${err.message}`);
        try { ensure(); } catch (_) { /* ignore */ }
    }
    return result;
}

function close(entry) {
    if (UFW) {
        run(UFW, ufwInputArgs(entry, true), { ignore: true });
        if (entry.method === 'iptables') run(UFW, ufwRouteArgs(entry, true), { ignore: true });
    }
    if (chainExists()) {
        applyRule('-D', inputSpec(entry));
        if (entry.method === 'iptables') applyRule('-D', forwardSpec(entry));
    }
    try { ensure(); } catch (_) { /* ignore */ }
}

module.exports = {
    status,
    ensure,
    flush,
    open,
    close
};
