'use strict';

const { execFileSync } = require('child_process');

const CHAIN = 'PORTFORWARD';
const COMMENT_PREFIX = 'pf';

function run(cmd, args, { ignore = false } = {}) {
    try {
        return execFileSync(cmd, args, {
            timeout: 8000,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        });
    } catch (err) {
        if (ignore) return '';
        const detail = (err.stderr || err.stdout || err.message || '').toString().trim();
        const wrapped = new Error(detail || `${cmd} failed`);
        wrapped.cause = err;
        throw wrapped;
    }
}

function iptablesHas(args) {
    try {
        execFileSync('iptables', ['-C', ...args], {
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

function hasUfwBin() {
    try {
        execFileSync('sh', ['-c', 'command -v ufw'], { timeout: 3000, stdio: ['ignore', 'pipe', 'pipe'] });
        return true;
    } catch (_) {
        return false;
    }
}

function ufwActive() {
    if (!hasUfwBin()) return false;
    try {
        const out = execFileSync('ufw', ['status'], {
            timeout: 5000,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return /Status:\s*active/i.test(out);
    } catch (_) {
        return false;
    }
}

function iptablesAvailable() {
    try {
        execFileSync('iptables', ['-L', '-n'], { timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
        return true;
    } catch (_) {
        return false;
    }
}

function status() {
    const installed = hasUfwBin();
    return {
        ufwInstalled: installed,
        ufwActive: installed && ufwActive(),
        iptables: iptablesAvailable()
    };
}

function ensure() {
    if (!iptablesAvailable()) return;
    if (!chainExists()) run('iptables', ['-N', CHAIN], { ignore: true });
    if (!iptablesHas(['INPUT', '-j', CHAIN])) {
        run('iptables', ['-I', 'INPUT', '1', '-j', CHAIN]);
    }
    if (!iptablesHas(['FORWARD', '-j', CHAIN])) {
        run('iptables', ['-I', 'FORWARD', '1', '-j', CHAIN]);
    }
    const established = [CHAIN, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'];
    if (!iptablesHas(established)) {
        run('iptables', ['-A', ...established]);
    }
}

function chainExists() {
    try {
        execFileSync('iptables', ['-n', '-L', CHAIN], {
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'pipe']
        });
        return true;
    } catch (_) {
        return false;
    }
}

function flush() {
    if (!chainExists()) return;
    run('iptables', ['-F', CHAIN], { ignore: true });
    const established = ['-A', CHAIN, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'];
    run('iptables', established, { ignore: true });
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
    const args = [action, CHAIN, ...spec];
    if (action === '-A' && iptablesHas([CHAIN, ...spec])) return;
    run('iptables', args, { ignore: action === '-D' });
}

function ufwAllowArgs(entry) {
    const args = ['--force', 'allow'];
    if (entry.inIface && entry.inIface !== '*') args.push('in', 'on', entry.inIface);
    args.push('to', 'any', 'port', String(entry.port), 'proto', entry.protocol);
    args.push('comment', `portforward-${entry.port}-${entry.protocol}`);
    return args;
}

function ufwDeleteArgs(entry) {
    const args = ['--force', 'delete', 'allow'];
    if (entry.inIface && entry.inIface !== '*') args.push('in', 'on', entry.inIface);
    args.push('to', 'any', 'port', String(entry.port), 'proto', entry.protocol);
    return args;
}

function ufwRouteArgs(entry, deleting) {
    const args = ['--force'];
    if (deleting) args.push('delete');
    args.push('route', 'allow');
    if (entry.inIface && entry.inIface !== '*') args.push('in', 'on', entry.inIface);
    if (entry.outIface) args.push('out', 'on', entry.outIface);
    args.push('to', entry.ip, 'port', String(entry.toPort), 'proto', entry.protocol);
    return args;
}

function open(entry) {
    ensure();
    applyRule('-A', inputSpec(entry));
    if (entry.method === 'iptables') applyRule('-A', forwardSpec(entry));
    if (!hasUfwBin()) return { ufw: false };
    try {
        run('ufw', ufwAllowArgs(entry));
        if (entry.method === 'iptables') run('ufw', ufwRouteArgs(entry, false));
        return { ufw: true };
    } catch (err) {
        console.error(`ufw allow failed: ${err.message}`);
        return { ufw: false, ufwError: err.message };
    }
}

function close(entry) {
    if (chainExists()) {
        applyRule('-D', inputSpec(entry));
        if (entry.method === 'iptables') applyRule('-D', forwardSpec(entry));
    }
    if (!hasUfwBin()) return;
    run('ufw', ufwDeleteArgs(entry), { ignore: true });
    if (entry.method === 'iptables') run('ufw', ufwRouteArgs(entry, true), { ignore: true });
}

module.exports = {
    status,
    ensure,
    flush,
    open,
    close
};
