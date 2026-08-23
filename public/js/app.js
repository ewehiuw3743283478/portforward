(() => {
    const $ = (sel, root = document) => root.querySelector(sel);
    const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

    $$('[data-flash-close]').forEach((btn) => {
        btn.addEventListener('click', () => btn.closest('[data-flash]')?.remove());
    });
    const flash = $('[data-flash]');
    if (flash) {
        setTimeout(() => flash.remove(), 8000);
    }

    $$('[data-toggle-password]').forEach((btn) => {
        btn.addEventListener('click', () => {
            const input = document.getElementById(btn.getAttribute('data-toggle-password'));
            if (!input) return;
            const show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.textContent = show ? 'Hide' : 'Show';
        });
    });

    const filter = $('#forward-filter');
    if (filter) {
        filter.addEventListener('input', () => {
            const q = filter.value.trim().toLowerCase();
            let visible = 0;
            $$('[data-forward-row]').forEach((row) => {
                const show = !q || row.dataset.search.includes(q);
                row.hidden = !show;
                if (show) visible += 1;
            });
            const empty = $('[data-filter-empty]');
            if (empty) empty.hidden = visible !== 0;
        });
    }

    $$('[data-copy]').forEach((btn) => {
        const original = btn.textContent;
        btn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(btn.dataset.copy);
                btn.textContent = 'Copied';
                setTimeout(() => { btn.textContent = original; }, 1400);
            } catch (_) { /* ignore */ }
        });
    });

    const listen = $('#listen-port');
    const dest = $('#dest-port');
    const same = $('#same-port');
    if (listen && dest && same) {
        const sync = () => {
            if (same.checked) dest.value = listen.value;
            dest.readOnly = same.checked;
        };
        same.addEventListener('change', sync);
        listen.addEventListener('input', sync);
        sync();
    }

    const form = $('#add-form');
    const preview = $('#mapping-preview');
    if (form && preview) {
        const update = () => {
            const ip = form.ip.value.trim() || 'destination';
            const port = form.port.value.trim() || 'port';
            const toPort = form.toPort.value.trim() || port;
            const proto = (form.querySelector('input[name="protocol"]:checked') || {}).value || 'tcp';
            const method = (form.querySelector('input[name="method"]:checked') || {}).value || 'socat';
            const inSel = form.inIface;
            const outSel = form.outIface;
            const inIface = inSel ? inSel.value : '*';
            const outIface = outSel ? outSel.value : '';
            const fw = form.querySelector('[name="firewall"]');
            const inOpt = inSel && inSel.selectedOptions[0];
            const inIp = inOpt && inOpt.textContent.includes('—')
                ? inOpt.textContent.split('—')[1].trim().split(/\s+/)[0]
                : (preview.dataset.publicIp || 'server');
            const listenHost = inIface === '*' ? (preview.dataset.publicIp || 'server') : (inIp || inIface);
            preview.replaceChildren();
            const listenEl = document.createElement('span');
            listenEl.className = 'mono';
            listenEl.textContent = `${listenHost}:${port}/${proto}`;
            const arrow = document.createElement('span');
            arrow.className = 'arrow';
            arrow.textContent = '→';
            const destEl = document.createElement('span');
            destEl.className = 'mono';
            destEl.textContent = `${ip}:${toPort}`;
            const via = document.createElement('span');
            via.className = 'muted';
            const inLabel = inIface === '*' ? 'all NICs' : inIface;
            const outLabel = outIface || 'auto';
            const fwLabel = fw && fw.checked ? 'firewall open' : 'firewall unchanged';
            via.textContent = `via ${method} · in ${inLabel} · out ${outLabel} · ${fwLabel}`;
            preview.append(listenEl, arrow, destEl, via);
        };
        form.addEventListener('input', update);
        form.addEventListener('change', update);
        update();
    }

    const dialog = $('#confirm-remove');
    if (dialog) {
        $$('[data-remove]').forEach((btn) => {
            btn.addEventListener('click', (event) => {
                event.preventDefault();
                dialog.querySelector('[name=port]').value = btn.dataset.port;
                dialog.querySelector('[name=protocol]').value = btn.dataset.protocol;
                dialog.querySelector('[name=method]').value = btn.dataset.method;
                dialog.querySelector('[data-remove-label]').textContent =
                    `${btn.dataset.port}/${btn.dataset.protocol} → ${btn.dataset.dest} (${btn.dataset.method})`;
                dialog.showModal();
            });
        });
        dialog.querySelector('[data-cancel]')?.addEventListener('click', () => dialog.close());
    }

    const otp = $('#otp');
    if (otp) {
        otp.addEventListener('input', () => {
            const raw = otp.value;
            if (raw.includes('-')) return;
            otp.value = raw.replace(/\D/g, '').slice(0, 6);
            if (otp.dataset.autosubmit === 'true' && otp.value.length === 6) {
                otp.form.requestSubmit();
            }
        });
    }
})();
