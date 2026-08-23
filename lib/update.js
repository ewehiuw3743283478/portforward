'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const PKG = require(path.join(ROOT, 'package.json'));
const SCRIPT = path.join(ROOT, 'scripts/update.sh');

function run(cmd, args, timeout = 45000) {
    return execFileSync(cmd, args, {
        cwd: ROOT,
        encoding: 'utf8',
        timeout,
        env: {
            ...process.env,
            GIT_TERMINAL_PROMPT: '0',
            GIT_ASKPASS: 'echo'
        },
        stdio: ['ignore', 'pipe', 'pipe']
    }).trim();
}

function isGitCheckout() {
    return fs.existsSync(path.join(ROOT, '.git'));
}

function git(args, timeout) {
    return run('git', args, timeout);
}

function upstreamRef() {
    try {
        return git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}']);
    } catch (_) { /* no upstream */ }
    let branch = 'master';
    try { branch = git(['rev-parse', '--abbrev-ref', 'HEAD']); } catch (_) { /* ignore */ }
    for (const guess of [`origin/${branch}`, 'origin/master', 'origin/main']) {
        try {
            git(['rev-parse', '--verify', guess]);
            return guess;
        } catch (_) { /* try next */ }
    }
    return null;
}

function status() {
    const info = {
        version: PKG.version || '0.0.0',
        git: isGitCheckout(),
        branch: null,
        commit: null,
        commitShort: null,
        remote: null,
        upstream: null,
        latest: null,
        latestShort: null,
        behind: null,
        dirty: false
    };
    if (!info.git) return info;
    try {
        info.branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);
        info.commit = git(['rev-parse', 'HEAD']);
        info.commitShort = git(['rev-parse', '--short', 'HEAD']);
        try { info.remote = git(['remote', 'get-url', 'origin']); } catch (_) { /* ignore */ }
        info.upstream = upstreamRef();
        const porcelain = git(['status', '--porcelain']);
        info.dirty = porcelain
            .split('\n')
            .filter(Boolean)
            .some((line) => !/ ports\.json$/.test(line));
        if (info.upstream) {
            try {
                info.latest = git(['rev-parse', info.upstream]);
                info.latestShort = git(['rev-parse', '--short', info.upstream]);
                info.behind = Number(git(['rev-list', '--count', `HEAD..${info.upstream}`])) || 0;
            } catch (_) { /* origin not fetched yet */ }
        }
    } catch (err) {
        info.error = err.stderr?.toString().trim() || err.message;
    }
    return info;
}

function fetchRemote() {
    if (!isGitCheckout()) {
        return { ok: false, error: 'This install is not a git checkout, so it cannot pull updates.' };
    }
    try {
        git(['fetch', '--quiet', 'origin'], 60000);
        return { ok: true, status: status() };
    } catch (err) {
        const detail = (err.stderr || err.stdout || err.message || '').toString().trim();
        return { ok: false, error: detail || 'git fetch failed', status: status() };
    }
}

function startApply() {
    if (!isGitCheckout()) {
        throw new Error('This install is not a git checkout, so it cannot pull updates.');
    }
    if (!fs.existsSync(SCRIPT)) {
        throw new Error('scripts/update.sh is missing.');
    }
    const unit = `portforward-update-${Date.now()}`;
    try {
        run('systemd-run', [
            '--no-block',
            '--collect',
            `--unit=${unit}`,
            '--description=Port Forward self-update',
            '/bin/bash', SCRIPT, '--from-panel'
        ], 15000);
    } catch (err) {
        const detail = (err.stderr || err.stdout || err.message || '').toString().trim();
        throw new Error(detail || 'Could not start the update job (systemd-run failed).');
    }
    return { unit };
}

module.exports = {
    ROOT,
    status,
    fetchRemote,
    startApply
};
