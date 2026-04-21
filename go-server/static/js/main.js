(function() {
    if (document.documentElement.classList.contains('covert-mode')) {
        document.body.classList.add('covert-mode');
        try {
            const env = localStorage.getItem('covertEnv') ?? 'tactical';
            document.body.classList.add('covert-' + env);
        } catch(_e) { /* localStorage unavailable — fall back to tactical */ // NOSONAR
            document.body.classList.add('covert-tactical');
        }
    }
    if (!document.getElementById('covertFilterOverlay')) {
        const overlay = document.createElement('div');
        overlay.id = 'covertFilterOverlay';
        overlay.className = 'covert-filter-overlay';
        document.body.appendChild(overlay);
    }
})();

(function() {
'use strict';

function parseIcon(html) {
    if (!html) return document.createTextNode('');
    const doc = new DOMParser().parseFromString(html, 'text/html');
    return doc.body.firstElementChild ?? document.createTextNode('');
}

function setIconAndText(el, iconHtml, text) {
    el.textContent = '';
    if (iconHtml) el.appendChild(parseIcon(iconHtml));
    if (text) el.appendChild(document.createTextNode(text));
}

function stripDots(s) {
    let d = s;
    while (d.charAt(0) === '.') d = d.slice(1);
    while (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
    return d;
}

function isValidLabel(label) {
    if (label.length === 0 || label.length > 63) return false;
    return !(label.startsWith('-') || label.endsWith('-'));
}

if ('serviceWorker' in navigator) {
    if (location.hostname === 'dnstool.it-help.tech') {
        navigator.serviceWorker.register('/sw.js').catch(function() {}); // NOSONAR
    } else {
        navigator.serviceWorker.getRegistrations().then(function(regs) {
            regs.forEach(function(r) { r.unregister(); });
        });
    }
}

function clearOverlayTimers(overlay) {
    overlay.classList.remove('is-active');
    if (overlay.dataset.timerId) {
        clearInterval(Number(overlay.dataset.timerId));
        delete overlay.dataset.timerId;
    }
    if (overlay.dataset.pollId) {
        clearInterval(Number(overlay.dataset.pollId));
        delete overlay.dataset.pollId;
    }
}

function resetAnalyzeButtons() {
    const reanalyzeBtn = document.getElementById('reanalyzeBtn');
    if (reanalyzeBtn && !reanalyzeBtn.classList.contains('disabled')) {
        reanalyzeBtn.textContent = ' Re-analyze';
        if (globalThis._icons) { reanalyzeBtn.insertBefore(parseIcon(globalThis._icons.sync), reanalyzeBtn.firstChild); }
    }
    const analyzeBtn = document.getElementById('analyzeBtn');
    if (analyzeBtn) {
        setIconAndText(analyzeBtn, globalThis._icons?.search ?? null, ' Analyze');
        analyzeBtn.disabled = false;
    }
    for (const b of document.querySelectorAll('.history-view-btn,.history-reanalyze-btn')) {
        b.classList.remove('disabled');
        b.removeAttribute('aria-disabled');
    }
}

globalThis.addEventListener('pageshow', function(e) {
    if (e.persisted) {
        for (const overlay of document.querySelectorAll('.loading-overlay')) {
            clearOverlayTimers(overlay);
        }
        resetTopologyNodes();
        document.body.classList.remove('loading');
        resetAnalyzeButtons();
    }
});

/*
 * Safari/WebKit Scan Overlay — Two Bugs, Two Fixes
 *
 * BUG 1 — Animation restart: WebKit does not restart CSS animations
 * when an element transitions from display:none to visible. The
 * double-rAF below forces a reflow so spinners/dots animate.
 *
 * BUG 2 — Timer freeze on navigation: Using location.href to start
 * a scan triggers a full-page navigation. WebKit kills all running
 * JS timers during navigation, so the overlay timer freezes at 0s.
 *
 * REQUIRED PATTERN for any scan action that shows an overlay:
 *   1. Call showOverlay(overlay) — activates overlay + fixes animations
 *   2. Call startStatusCycle(overlay) — starts timer + phase rotation
 *   3. Use fetch(url) to submit the scan (keeps JS alive)
 *   4. On response: parse with DOMParser and replace document element
 *   5. Update URL: history.replaceState(null, '', resp.url)
 *   6. Fallback: .catch → location.href (graceful degradation)
 *
 * NEVER use location.href or globalThis.location to start a scan that
 * depends on an active overlay timer. See index.html and history.html
 * for reference implementations.
 */
function showOverlay(overlay) {
    if (!overlay) return;
    resetTelemLog();
    resetMeters();
    overlay.classList.add('is-active');
    overlay.offsetHeight; // NOSONAR — force reflow for Safari animation restart
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            const els = overlay.querySelectorAll('.loading-spinner, .loading-spinner i, .loading-dots span');
            const animated = [];
            for (const el of els) {
                const anim = getComputedStyle(el).animationName;
                if (anim && anim !== 'none') animated.push(el);
            }
            for (const el of animated) el.classList.add('anim-restart');
            if (animated.length) void animated[0].offsetWidth; // NOSONAR — single reflow to restart all animations (Safari)
            for (const el of animated) el.classList.remove('anim-restart');
        });
    });
}

function startStatusCycle(overlayEl) {
    const timerEl = overlayEl.querySelector('.scan-overlay-timer') ?? overlayEl.querySelector('.loading-elapsed span');
    const noteEl = overlayEl.querySelector('.scan-overlay-note');
    const startTime = Date.now();

    if (timerEl) {
        timerEl.textContent = '0s';
        const timerId = setInterval(function() {
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            timerEl.textContent = elapsed + 's';
        }, 1000);
        overlayEl.dataset.timerId = timerId;
    }
    if (noteEl) {
        setTimeout(function() {
            noteEl.classList.add('u-opacity-visible');
        }, 6000);
    }

    const topoEl = overlayEl.querySelector('.scan-topology');
    if (topoEl) {
        topoEl.setAttribute('aria-hidden', 'false');
    }
    if (globalThis._startGlobeAnimation) {
        requestAnimationFrame(function() {
            setTimeout(globalThis._startGlobeAnimation, 80);
        });
    }
}

const PHASE_DONE_CLASSES = ['phase-done-dns','phase-done-email','phase-done-dnssec','phase-done-ct','phase-done-smtp','phase-done-policy','phase-done-registrar','phase-done-engine','phase-done-web3'];
const PHASE_RUNNING_CLASSES = ['phase-running-dns','phase-running-email','phase-running-dnssec','phase-running-ct','phase-running-smtp','phase-running-policy','phase-running-registrar','phase-running-engine','phase-running-web3'];
const SUB_RUNNING_CLASSES = ['sub-running-dns','sub-running-email','sub-running-dnssec','sub-running-ct','sub-running-smtp','sub-running-policy','sub-running-registrar','sub-running-engine','sub-running-web3'];
const CONN_DONE_CLASSES = ['conn-done-dns','conn-done-email','conn-done-dnssec','conn-done-ct','conn-done-smtp','conn-done-policy','conn-done-registrar','conn-done-engine','conn-done-web3'];
const CONN_ACTIVE_CLASSES = ['conn-active-dns','conn-active-email','conn-active-dnssec','conn-active-ct','conn-active-smtp','conn-active-policy','conn-active-registrar','conn-active-engine','conn-active-web3'];
const RESOLVER_KEYS = ['cf','g','q9','od','eu'];
const RES_DONE_CLASSES = ['res-done-cf','res-done-g','res-done-q9','res-done-od','res-done-eu'];

function removeClasses(el, classes) {
    for (const c of classes) el.classList.remove(c);
}

function resetResolverElements(els) {
    for (const el of els) {
        el.classList.remove('res-running');
        removeClasses(el, RES_DONE_CLASSES);
    }
}

function applyResolverStatus(dots, lines, labels, rk, dnsStatus) {
    if (dnsStatus === 'running') {
        for (const d of dots) d.classList.add('res-running');
        for (const l of lines) l.classList.add('res-running');
    } else if (dnsStatus === 'done') {
        for (const d of dots) d.classList.add('res-done-' + rk);
        for (const l of lines) l.classList.add('res-done-' + rk);
        for (const lb of labels) lb.classList.add('res-label-done');
    }
}

function updateResolverDots(topoEl, dnsStatus) {
    for (const rk of RESOLVER_KEYS) {
        const dots = topoEl.querySelectorAll('.topo-res-dot[data-resolver="' + rk + '"]');
        const lines = topoEl.querySelectorAll('.topo-res-line[data-resolver="' + rk + '"]');
        const labels = topoEl.querySelectorAll('.topo-res-label[data-resolver="' + rk + '"]');
        resetResolverElements(dots);
        resetResolverElements(lines);
        for (const lb of labels) lb.classList.remove('res-label-done');
        applyResolverStatus(dots, lines, labels, rk, dnsStatus);
    }
}

function resetPhaseNode(node, taskEl, info) {
    node.classList.remove('phase-running', 'phase-done');
    removeClasses(node, PHASE_DONE_CLASSES);
    removeClasses(node, PHASE_RUNNING_CLASSES);
    if (taskEl) {
        taskEl.classList.remove('sub-done');
        removeClasses(taskEl, SUB_RUNNING_CLASSES);
        if (info.tasks_total > 0) {
            taskEl.textContent = (info.tasks_done ?? 0) + '/' + info.tasks_total;
        }
    }
}

function applyPhaseConnectors(topoEl, group, pkey, isDone) {
    for (const line of topoEl.querySelectorAll('.topo-connector')) {
        if (line.dataset.from !== group) continue;
        if (isDone) {
            line.classList.remove('active');
            removeClasses(line, CONN_ACTIVE_CLASSES);
            line.classList.add('complete', 'conn-done-' + pkey);
        } else {
            line.classList.add('active', 'conn-active-' + pkey);
        }
    }
}

function updatePhaseNode(topoEl, node, info, pkey, taskEl, durEl, group) {
    const prevStatus = node.dataset.lastStatus;
    if (prevStatus === info.status) {
        if (taskEl && info.tasks_total > 0) {
            taskEl.textContent = (info.tasks_done ?? 0) + '/' + info.tasks_total;
        }
        return;
    }
    resetPhaseNode(node, taskEl, info);
    node.dataset.lastStatus = info.status;
    if (info.status === 'done') {
        node.classList.add('phase-done', 'phase-done-' + pkey);
        if (taskEl) taskEl.classList.add('sub-done');
        if (durEl && info.duration_ms > 0) {
            durEl.textContent = (info.duration_ms / 1000).toFixed(1) + 's';
            durEl.classList.add('visible');
        }
        applyPhaseConnectors(topoEl, group, pkey, true);
    } else if (info.status === 'running') {
        node.classList.add('phase-running', 'phase-running-' + pkey);
        if (taskEl) taskEl.classList.add('sub-running-' + pkey);
        applyPhaseConnectors(topoEl, group, pkey, false);
    }
}

function updateTopologyFromProgress(data) {
    const topoEl = document.getElementById('scanTopology') ?? document.querySelector('.scan-topology');
    if (!topoEl || !data?.phases) return;
    const phases = data.phases;
    const dnsPhase = phases['dns_records'];
    if (dnsPhase && topoEl.dataset.lastDnsStatus !== dnsPhase.status) {
        topoEl.dataset.lastDnsStatus = dnsPhase.status;
        updateResolverDots(topoEl, dnsPhase.status);
    }
    for (const group of Object.keys(phases)) {
        const info = phases[group];
        const node = topoEl.querySelector('[data-phase="' + group + '"]');
        const durEl = topoEl.querySelector('[data-dur="' + group + '"]');
        const taskEl = topoEl.querySelector('[data-tasks="' + group + '"]');
        if (!node) continue;
        const pkey = node.dataset.pkey ?? 'dns';
        updatePhaseNode(topoEl, node, info, pkey, taskEl, durEl, group);
    }
}

function followRedirect(url, overlay, analyzeBtn) {
    fetch(url, {
        headers: { 'X-Requested-With': 'fetch' },
        redirect: 'follow'
    }).then(function(resp) {
        return resp.text().then(function(html) { hideOverlayAndReset(overlay, analyzeBtn); applyFetchedPage(html, resp.url); });
    }).catch(function() {
        hideOverlayAndReset(overlay, analyzeBtn);
        globalThis.location.href = url;
    });
}

const TELEM_PHASE_NAMES = {
    dns_records: 'DNS Records',
    email_auth: 'Email Auth',
    dnssec_dane: 'DNSSEC/DANE',
    ct_subdomains: 'CT/Subdomains',
    smtp_transport: 'SMTP Transport',
    policy_records: 'Policy Records',
    registrar_infra: 'Registrar/Infra',
    web3_analysis: 'Web3',
    analysis_engine: 'ICIE Engine'
};
let _telemPollN = 0;
let _telemPrevPhases = {};
let _telemStartT = 0;
let _telemCompleteLogged = false;

function resetTelemLog() {
    _telemPollN = 0;
    _telemPrevPhases = {};
    _telemStartT = 0;
    _telemCompleteLogged = false;
    const body = document.getElementById('telemLogBody');
    if (body) body.innerHTML = '';
    const cnt = document.getElementById('telemPollCount');
    if (cnt) cnt.textContent = '0 polls';
}

function appendTelemEntry(elapsed, phaseName, status, detail) {
    const body = document.getElementById('telemLogBody');
    if (!body) return;
    let row = document.createElement('div');
    row.className = 'telem-entry';
    const ts = document.createElement('span');
    ts.className = 'telem-ts';
    ts.textContent = elapsed;
    const ph = document.createElement('span');
    ph.className = 'telem-phase';
    ph.textContent = phaseName;
    const st = document.createElement('span');
    st.className = 'telem-status telem-status-' + status;
    st.textContent = status;
    row.appendChild(ts);
    row.appendChild(ph);
    row.appendChild(st);
    if (detail) {
        const dt = document.createElement('span');
        dt.className = 'telem-detail';
        dt.textContent = detail;
        row.appendChild(dt);
    }
    body.appendChild(row);
    body.scrollTop = body.scrollHeight;
}

function fmtTelemElapsed(ms) {
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    const sec = s % 60;
    const frac = Math.floor((ms % 1000) / 100);
    if (m > 0) return m + ':' + (sec < 10 ? '0' : '') + sec + '.' + frac;
    return sec + '.' + frac + 's';
}

function updateTelemLog(data) { // NOSONAR — telemetry UI update function
    if (!data?.phases) return;
    if (!_telemStartT) _telemStartT = Date.now();
    _telemPollN++;
    const cnt = document.getElementById('telemPollCount');
    if (cnt) cnt.textContent = _telemPollN + (_telemPollN === 1 ? ' poll' : ' polls');
    const now = Date.now();
    const elapsed = fmtTelemElapsed(now - _telemStartT);
    for (const group of Object.keys(data.phases)) {
        const info = data.phases[group];
        const prev = _telemPrevPhases[group];
        if (prev === info.status) continue;
        _telemPrevPhases[group] = info.status;
        const name = TELEM_PHASE_NAMES[group] || group;
        let detail = '';
        if (info.status === 'done' && info.duration_ms) {
            detail = info.duration_ms + 'ms';
        } else if (info.status === 'running' && info.tasks_done !== undefined && info.tasks_total !== undefined) {
            detail = info.tasks_done + '/' + info.tasks_total;
        }
        appendTelemEntry(elapsed, name, info.status, detail);
    }
    if (data.status === 'complete' && !_telemCompleteLogged) {
        _telemCompleteLogged = true;
        appendTelemEntry(elapsed, 'Scan', 'done', 'complete');
    }
}

let _meterDurations = {};
let _meterStartT = 0;

function resetMeters() {
    _meterDurations = {};
    _meterStartT = 0;
    const phaseBar = document.getElementById('meterPhaseBar');
    const taskBar = document.getElementById('meterTaskBar');
    if (phaseBar) phaseBar.style.width = '0%';
    if (taskBar) taskBar.style.width = '0%';
    const phaseVal = document.getElementById('meterPhaseVal');
    if (phaseVal) phaseVal.textContent = '0 / 9';
    const taskVal = document.getElementById('meterTaskVal');
    if (taskVal) taskVal.textContent = '0';
    const pollVal = document.getElementById('meterPollVal');
    if (pollVal) pollVal.textContent = '0';
    const elVal = document.getElementById('meterElapsedVal');
    if (elVal) elVal.textContent = '0.0s';
    const bars = document.querySelectorAll('[data-mbar]');
    for (const bar of bars) bar.style.width = '0%';
    const msEls = document.querySelectorAll('[data-mms]');
    for (const el of msEls) el.textContent = '\u2014';
    const rows = document.querySelectorAll('[data-mrow]');
    for (const row of rows) {
        row.classList.remove('meter-row-done', 'meter-row-running');
        const msEl = row.querySelector('[data-mms]');
        if (msEl) msEl.classList.remove('meter-ms-active');
    }
    const avgEl = document.getElementById('meterAvgMs');
    const minEl = document.getElementById('meterMinMs');
    const maxEl = document.getElementById('meterMaxMs');
    if (avgEl) avgEl.textContent = '\u2014';
    if (minEl) minEl.textContent = '\u2014';
    if (maxEl) maxEl.textContent = '\u2014';
}

function updateMeters(data) { // NOSONAR — UI update function, complexity is inherent
    if (!data?.phases) return;
    if (!_meterStartT) _meterStartT = Date.now();
    const phases = data.phases;
    let doneCount = 0;
    let totalTasks = 0;
    let doneTasks = 0;
    const durations = [];
    let maxDur = 1;
    for (const g of Object.keys(phases)) {
        const info = phases[g];
        if (info.status === 'done') {
            doneCount++;
            if (info.duration_ms) {
                _meterDurations[g] = info.duration_ms;
                durations.push(info.duration_ms);
            }
        }
        if (info.tasks_total) totalTasks += info.tasks_total;
        if (info.tasks_done) doneTasks += info.tasks_done;
    }
    const phaseBar = document.getElementById('meterPhaseBar');
    const phaseVal = document.getElementById('meterPhaseVal');
    if (phaseBar) phaseBar.style.width = Math.round((doneCount / 9) * 100) + '%';
    if (phaseVal) phaseVal.textContent = doneCount + ' / 9';
    const taskBar = document.getElementById('meterTaskBar');
    const taskVal = document.getElementById('meterTaskVal');
    const taskPct = totalTasks > 0 ? Math.round((doneTasks / totalTasks) * 100) : 0;
    if (taskBar) taskBar.style.width = taskPct + '%';
    if (taskVal) taskVal.textContent = doneTasks + (totalTasks > 0 ? ' / ' + totalTasks : '');
    const pollVal = document.getElementById('meterPollVal');
    if (pollVal) pollVal.textContent = '' + _telemPollN;
    const elVal = document.getElementById('meterElapsedVal');
    if (elVal) elVal.textContent = fmtTelemElapsed(Date.now() - _meterStartT);
    for (const dur of durations) {
        if (dur > maxDur) maxDur = dur;
    }
    for (const group of Object.keys(phases)) {
        const ph = phases[group];
        const row = document.querySelector('[data-mrow="' + group + '"]');
        if (!row) continue;
        const bar = row.querySelector('[data-mbar]');
        const msEl = row.querySelector('[data-mms]');
        row.classList.remove('meter-row-done', 'meter-row-running');
        if (ph.status === 'running') {
            row.classList.add('meter-row-running');
            if (bar) bar.style.width = '100%';
        } else if (ph.status === 'done') {
            row.classList.add('meter-row-done');
            const dur = _meterDurations[group] || 0;
            if (bar) bar.style.width = Math.round((dur / maxDur) * 100) + '%';
            if (msEl) {
                msEl.textContent = dur + 'ms';
                msEl.classList.add('meter-ms-active');
            }
        }
    }
    if (durations.length > 0) {
        let sum = 0, mn = durations[0], mx = durations[0];
        for (const d of durations) {
            sum += d;
            if (d < mn) mn = d;
            if (d > mx) mx = d;
        }
        const avg = Math.round(sum / durations.length);
        const avgEl = document.getElementById('meterAvgMs');
        const minEl = document.getElementById('meterMinMs');
        const maxEl = document.getElementById('meterMaxMs');
        if (avgEl) avgEl.textContent = avg + 'ms';
        if (minEl) minEl.textContent = mn + 'ms';
        if (maxEl) maxEl.textContent = mx + 'ms';
    }
}

function handlePollData(data, ctx) {
    if (!data) {
        if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(ctx.overlay, ctx.btn); }
        return;
    }
    updateTopologyFromProgress(data);
    updateTelemLog(data);
    updateMeters(data);
    if (data.status === 'failed') {
        clearInterval(ctx.pollId);
        hideOverlayAndReset(ctx.overlay, ctx.btn);
        showFlashAlert(data.error || 'Analysis failed. Please try again.', ctx.overlay ? ctx.overlay.parentNode : document.body);
        return;
    }
    if (data.status === 'complete' && data.redirect_url) {
        clearInterval(ctx.pollId);
        followRedirect(data.redirect_url, ctx.overlay, ctx.btn);
    } else if (data.status === 'complete') {
        clearInterval(ctx.pollId);
        hideOverlayAndReset(ctx.overlay, ctx.btn);
    }
    if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(ctx.overlay, ctx.btn); }
}

function startProgressPolling(token, overlay, analyzeBtn) {
    const ctx = { failures: 0, pollId: 0, overlay: overlay, btn: analyzeBtn };
    ctx.pollId = setInterval(function() {
        fetch('/api/scan/progress/' + token).then(function(resp) {
            if (!resp.ok) { ctx.failures++; return null; }
            ctx.failures = 0;
            return resp.json();
        }).then(function(data) {
            handlePollData(data, ctx);
        }).catch(function() {
            ctx.failures++;
            if (ctx.failures >= 3) { clearInterval(ctx.pollId); hideOverlayAndReset(overlay, analyzeBtn); }
        });
    }, 500);
    if (overlay) {
        overlay.dataset.pollId = ctx.pollId;
    }
    return ctx.pollId;
}

function hideOverlayAndReset(overlay, btn) {
    if (overlay) {
        overlay.classList.remove('is-active');
        if (overlay.dataset.timerId) {
            clearInterval(Number(overlay.dataset.timerId));
            delete overlay.dataset.timerId;
        }
        if (overlay.dataset.pollId) {
            clearInterval(Number(overlay.dataset.pollId));
            delete overlay.dataset.pollId;
        }
    }
    resetTopologyNodes();
    document.body.classList.remove('loading');
    if (btn) {
        setIconAndText(btn, globalThis._icons?.search ?? null, ' Analyze');
        btn.disabled = false;
    }
}

function showFlashAlert(message, container) {
    const flash = document.createElement('div');
    flash.className = 'alert alert-warning alert-dismissible fade show mt-3';
    flash.role = 'alert';
    flash.textContent = message;
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'btn-close';
    closeBtn.dataset.bsDismiss = 'alert';
    flash.appendChild(closeBtn);
    const target = container ?? document.body;
    const form = target.querySelector('#domainForm');
    if (form?.parentNode) {
        form.parentNode.insertBefore(flash, form);
    } else {
        target.insertBefore(flash, target.firstChild);
    }
}

function resetTopologyNodes() {
    const topoEl = document.getElementById('scanTopology') ?? document.querySelector('.scan-topology');
    if (!topoEl) return;
    topoEl.setAttribute('aria-hidden', 'true');
    if (_globeAnim) { cancelAnimationFrame(_globeAnim); _globeAnim = null; }
    delete topoEl.dataset.lastDnsStatus;
    for (const g of topoEl.querySelectorAll('[data-phase]')) {
        delete g.dataset.lastStatus;
    }
    for (const n of topoEl.querySelectorAll('.topo-node')) {
        n.classList.remove('phase-running', 'phase-done');
        removeClasses(n, PHASE_DONE_CLASSES);
        removeClasses(n, PHASE_RUNNING_CLASSES);
    }
    for (const d of topoEl.querySelectorAll('.topo-dur')) {
        d.textContent = '';
        d.classList.remove('visible');
    }
    for (const t of topoEl.querySelectorAll('.topo-sub[data-tasks]')) {
        t.classList.remove('sub-done');
        removeClasses(t, SUB_RUNNING_CLASSES);
    }
    for (const c of topoEl.querySelectorAll('.topo-connector')) {
        c.classList.remove('active', 'complete');
        removeClasses(c, CONN_DONE_CLASSES);
        removeClasses(c, CONN_ACTIVE_CLASSES);
    }
    for (const d of topoEl.querySelectorAll('.topo-res-dot')) {
        d.classList.remove('res-running');
        removeClasses(d, RES_DONE_CLASSES);
    }
    for (const l of topoEl.querySelectorAll('.topo-res-line')) {
        l.classList.remove('res-running');
        removeClasses(l, RES_DONE_CLASSES);
    }
    for (const lb of topoEl.querySelectorAll('.topo-res-label')) {
        lb.classList.remove('res-label-done');
    }
}

function isBareTopLevelDomain(domain) {
    if (!domain) return false;
    let d = domain.toLowerCase();
    while (d.charAt(0) === '.') d = d.slice(1);
    while (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
    if (!d || d.length > 63) return false;
    const labels = d.split('.');
    return labels.length === 1 && (/^[a-zA-Z]{2,}$/.test(labels[0]) || labels[0].startsWith('xn--'));
}

function swapToTLDScanPhases(overlay) {
    const checklist = overlay.querySelector('.scan-overlay-checklist') ?? overlay.querySelector('#scanChecklist');
    if (!checklist) return;
    const isCovert = document.body.classList.contains('covert-mode');
    const phases = [
        { delay: 0, normal: 'DNS records \u2014 Cloudflare, Google, Quad9, OpenDNS, DNS4EU', covert: 'Enumerating DNS across 5 resolvers\u2026' },
        { delay: 1200, normal: 'DNSSEC chain of trust \u2014 DS/DNSKEY validation', covert: 'Testing DNS poison resistance \u2014 DNSSEC, DANE' },
        { delay: 2500, normal: 'Nameserver fleet \u2014 reachability, ASN diversity, SOA sync', covert: 'Probing NS fleet \u2014 reachability, ASN, SOA serial' },
        { delay: 3500, normal: 'Delegation consistency \u2014 glue, TTL, DS alignment', covert: 'Auditing delegation chain \u2014 glue, DS, TTL drift' },
        { delay: 5000, normal: 'DNS server security \u2014 Nmap probes', covert: 'Nmap fingerprinting nameservers\u2026' },
        { delay: 7000, normal: 'SOA compliance \u2014 timers, zone health', covert: 'Checking SOA timers against RFC 1912' },
        { delay: 9000, normal: 'Registrar \u0026 RDAP analysis', covert: 'Mapping registrar \u0026 RDAP footprint' },
        { delay: 12000, normal: 'Classifying \u0026 Interpreting Intelligence', covert: 'Correlating attack surface\u2026' }
    ];
    checklist.textContent = '';
    for (const p of phases) {
        const div = document.createElement('div');
        div.className = 'scan-phase';
        div.dataset.delay = p.delay;
        const iconWrap = document.createElement('span');
        iconWrap.className = 'scan-icon scan-pending';
        iconWrap.appendChild(parseIcon(globalThis._icons?.spinner ?? ''));
        iconWrap.setAttribute('aria-hidden', 'true');
        const span = document.createElement('span');
        span.className = isCovert ? 'covert-show' : 'covert-hide';
        span.textContent = isCovert ? p.covert : p.normal;
        div.appendChild(iconWrap);
        div.appendChild(span);
        checklist.appendChild(div);
    }
}

function showCovertTLDToast(domain, callback) {
    const existing = document.getElementById('tldReconToast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'tldReconToast';
    toast.role = 'alert';
    toast.ariaLive = 'assertive';
    toast.className = 'tld-recon-toast';
    const toastTitle = document.createElement('div');
    toastTitle.className = 'tld-recon-toast-title';
    toastTitle.appendChild(parseIcon(globalThis._icons.globe));
    toastTitle.appendChild(document.createTextNode('Planning to hack the planet, Zero Cool?'));
    const toastBody = document.createElement('div');
    toastBody.className = 'tld-recon-toast-body';
    toastBody.textContent = 'Bare\u2011TLD recon maps registry infrastructure only \u2014 DNSSEC, NS delegation, CAA, registrar, Nmap, SVCB. No SPF/DKIM/DMARC at zone scope.';
    const toastFooter = document.createElement('div');
    toastFooter.className = 'tld-recon-toast-footer';
    toastFooter.appendChild(parseIcon(globalThis._icons.satellite));
    toast.appendChild(toastTitle);
    toast.appendChild(toastBody);
    toast.appendChild(toastFooter);
    toastFooter.appendChild(document.createTextNode('Scanning .' + domain.toUpperCase() + ' \u2014 infrastructure vectors only'));

    document.body.appendChild(toast);

    toast.addEventListener('click', function() {
        toast.remove();
    });

    setTimeout(function() {
        toast.classList.add('tld-recon-toast-dismissing');
        setTimeout(function() {
            toast.remove();
            if (callback) callback();
        }, 300);
    }, 4000);
}

function isValidDomain(domain) {
    if (!domain) return false;
    const d = stripDots(domain);
    if (d.length > 253 || d.length === 0) return false;
    const labels = d.split('.');
    if (labels.length === 1) {
        return /^[a-zA-Z]{2,}$/.test(labels[0]) || labels[0].startsWith('xn--');
    }
    for (const label of labels) {
        if (!isValidLabel(label)) return false;
    }
    const lastLabel = labels[labels.length - 1];
    if (/^\d+$/.test(lastLabel)) return false;
    if (!/[^\u0020-\u007F]/.test(d)) {
        for (const label of labels) {
            if (!/^[a-zA-Z0-9-]+$/.test(label)) return false;
        }
    }
    return true;
}

function fetchAndApplyPage(url, options, overlay, btn) {
    return fetch(url, options).then(function(resp) {
        return resp.text().then(function(html) { hideOverlayAndReset(overlay, btn); applyFetchedPage(html, resp.url); });
    });
}

function performFallbackAnalysis(domain, isCovert, overlay, btn) {
    const url = '/analyze?domain=' + encodeURIComponent(domain) + (isCovert ? '&covert=1' : '') + '&refresh=' + Date.now();
    let respUrl;
    fetch(url, {
        headers: { 'X-Requested-With': 'fetch' },
        redirect: 'follow'
    }).then(function(resp) {
        respUrl = resp.url;
        return resp.text();
    }).then(function(html) {
        hideOverlayAndReset(overlay, btn);
        applyFetchedPage(html, respUrl);
    }).catch(function() {
        globalThis.location.href = url;
    });
}

function applyFetchedPage(html, respUrl) {
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    document.documentElement.replaceWith(parsed.documentElement);
    globalThis.scrollTo(0, 0);
    const modeMeta = document.querySelector('meta[name="x-report-mode"]');
    const idEl = document.querySelector('[data-analysis-id]');
    const mode = modeMeta ? modeMeta.getAttribute('content') : '';
    const aid = idEl ? idEl.dataset.analysisId : '';
    if (aid && mode) {
        globalThis.history.replaceState(null, '', '/analysis/' + aid + '/view/' + mode);
    } else if (respUrl && respUrl !== globalThis.location.href) {
        globalThis.history.replaceState(null, '', respUrl);
    }
}

function resetCopyBtn(btn) {
    btn.textContent = '';
    btn.appendChild(parseIcon(globalThis._icons.copy));
    btn.classList.remove('copied');
}

function handleCopyResult(btn, success) {
    btn.textContent = '';
    btn.appendChild(parseIcon(success ? globalThis._icons.check : globalThis._icons.times));
    if (success) btn.classList.add('copied');
    setTimeout(function() { resetCopyBtn(btn); }, 1500);
}

function createCopyHandler(codeBlock, btn) {
    return function(e) {
        e.stopPropagation();
        let copyText = '';
        for (const node of codeBlock.childNodes) {
            if (node !== btn && !node.classList?.contains('copy-btn')) {
                copyText += node.textContent;
            }
        }
        copyText = copyText.trim();

        navigator.clipboard.writeText(copyText).then(
            function() { handleCopyResult(btn, true); }
        ).catch(
            function() { handleCopyResult(btn, false); }
        );
    };
}

const covertEnvClasses = ['covert-submarine', 'covert-tactical', 'covert-basement'];

function clearCovertEnv() {
    for (const c of covertEnvClasses) document.body.classList.remove(c);
}

function getCovertEnv() {
    try { return localStorage.getItem('covertEnv') ?? 'tactical'; } catch(_e) { return 'tactical'; } // NOSONAR
}

function hasAcceptedROE() {
    try { return localStorage.getItem('roeAccepted') === '1'; } catch(_e) { return false; } // NOSONAR
}

function markROEAccepted() {
    try { localStorage.setItem('roeAccepted', '1'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

let _morseAudio = null;
function _ensureMorseAudio() {
    if (!_morseAudio) {
        try {
            _morseAudio = new Audio('/static/audio/morse-hack-the-planet.m4a');
            _morseAudio.volume = 0.4;
            _morseAudio.preload = 'auto';
        } catch(_e) { /* Audio API unavailable */ } // NOSONAR
    }
    return _morseAudio;
}
function playMorseEasterEgg() {
    try {
        const a = _ensureMorseAudio();
        if (a) {
            a.currentTime = 0;
            a.play().catch(function(err) {
                console.warn('Morse audio blocked by autoplay policy:', err.message);
            });
        }
    } catch(_e) { /* intentionally empty — Audio API unavailable in some contexts */ } // NOSONAR
}

function updateEnvButtons(env) {
    for (const b of document.querySelectorAll('.covert-env-btn')) {
        b.classList.toggle('active', b.dataset.env === env);
    }
}

const covertThemeColors = { submarine: '#0a0404', tactical: '#1a0808', basement: '#140606' };
const defaultThemeColors = [];

function updateThemeColor(env) {
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    if (!defaultThemeColors.length && metas.length) {
        for (const m of metas) defaultThemeColors.push(m.getAttribute('content') ?? '#0d1117');
    }
    const color = covertThemeColors[env] ?? covertThemeColors.tactical;
    for (const m of metas) m.setAttribute('content', color);
}

function restoreThemeColor() {
    const metas = document.querySelectorAll('meta[name="theme-color"]');
    let i = 0;
    for (const m of metas) { m.setAttribute('content', defaultThemeColors[i] ?? '#0d1117'); i++; }
}

function setCovertEnv(env) {
    clearCovertEnv();
    if (env && covertEnvClasses.includes('covert-' + env)) {
        document.body.classList.add('covert-' + env);
    } else {
        document.body.classList.add('covert-tactical');
        env = 'tactical';
    }
    try { localStorage.setItem('covertEnv', env); } catch(_e) { /* storage unavailable */ } // NOSONAR
    updateEnvButtons(env);
    if (document.body.classList.contains('covert-mode')) { updateThemeColor(env); }
}

function exitFullscreenSafe() {
    const activeFs = document.fullscreenElement || document.webkitFullscreenElement;
    if (!activeFs) return;
    try { if (document.exitFullscreen) { document.exitFullscreen(); } else if (document.webkitExitFullscreen) { document.webkitExitFullscreen(); } } catch(_e) { /* intentional */ } // NOSONAR
}

function setCovertMode(active) {
    if (active) {
        document.body.classList.add('covert-mode');
        setCovertEnv(getCovertEnv());
    } else {
        document.body.classList.remove('covert-mode');
        clearCovertEnv();
        restoreThemeColor();
        exitFullscreenSafe();
    }
    const toggle = document.getElementById('covertToggle');
    if (toggle) { toggle.setAttribute('aria-pressed', active ? 'true' : 'false'); }
    try { localStorage.setItem('covertMode', active ? '1' : '0'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function saveScrollPosition() {
    try { sessionStorage.setItem('covert_scroll_y', String(globalThis.scrollY)); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function activateCovertOrSwitch() {
    const idEl = document.querySelector('[data-analysis-id]');
    const modeMeta = document.querySelector('meta[name="x-report-mode"]');
    if (idEl && modeMeta) {
        const aid = idEl.dataset.analysisId;
        const cur = (modeMeta.getAttribute('content') ?? 'E').toUpperCase();
        if (aid && (cur === 'E' || cur === 'C')) {
            const target = cur === 'E' ? 'C' : 'E';
            saveScrollPosition();
            globalThis.location.href = '/analysis/' + aid + '/view/' + target;
            return;
        }
    }
    setCovertMode(!document.body.classList.contains('covert-mode'));
}

function handleAnalyzeLinkClick(e) {
    e.preventDefault();
    const link = e.currentTarget;
    const overlay = document.getElementById('loadingOverlay');
    const url = new URL(link.href, globalThis.location.origin);
    const domain = url.searchParams.get('domain') ?? '';
    if (overlay) {
        const domainEl = overlay.querySelector('.scan-overlay-domain');
        if (domainEl) domainEl.textContent = domain;
        showOverlay(overlay);
        startStatusCycle(overlay);
    }
    document.body.classList.add('loading');
    fetchAndApplyPage(link.href, {
        headers: { 'X-Requested-With': 'fetch' },
        redirect: 'follow'
    }, overlay, null).catch(function() {
        hideOverlayAndReset(overlay, null);
        globalThis.location.href = link.href;
    });
}

function privacyWasDismissed() {
    try { if (localStorage.getItem('privacyAck') === '1') return true; } catch(_e) { /* storage unavailable */ } // NOSONAR
    return false;
}
function persistPrivacyDismiss() {
    try { localStorage.setItem('privacyAck', '1'); } catch(_e) { /* storage unavailable */ } // NOSONAR
    // Cookie fallback removed (Qualys QID 150122/150123): the JS-set cookie
    // could not carry HttpOnly/Secure attributes. localStorage is universally
    // available in supported browsers; no fallback needed.
}
function initPrivacyBanner() {
    const banner = document.getElementById('privacyBanner');
    if (!banner) { return; }
    if (privacyWasDismissed()) { banner.remove(); return; }
    function dismissBanner(e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        persistPrivacyDismiss();
        banner.classList.add('d-none');
        if (banner.parentNode) { banner.remove(); }
    }
    const acceptBtn = document.getElementById('privacyAccept');
    if (acceptBtn) {
        acceptBtn.onclick = dismissBanner;
    }
    banner.addEventListener('click', function(e) {
        if (e.target.closest?.('#privacyAccept')) {
            dismissBanner(e);
        }
    });
}

function initPrivacyToggle() {
    const privToggle = document.getElementById('privacyToggle');
    const privDetail = document.getElementById('privacyDetail');
    if (privToggle && privDetail) {
        function togglePrivacy() { privDetail.classList.toggle('d-none'); }
        privToggle.addEventListener('click', togglePrivacy);
        privToggle.addEventListener('keydown', function(e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); togglePrivacy(); } });
    }
}

let _globeAnim = null;

function stopGlobeAnimation() {
    if (_globeAnim) { cancelAnimationFrame(_globeAnim); _globeAnim = null; }
}

function initGlobeMotion() {
    const GC = globalThis.GlobeCore;
    if (!GC) return;
    const RESOLVER_POPS = GC.RESOLVER_POPS;
    const OWN_PROBES = GC.OWN_PROBES;

    const globe = GC.createGlobeState();
    GC.loadTexture(globe);

    const convergePt = { x: 0, y: 0 };
    let signalParticles = [];
    let particlesInitialized = false;

    function drawSignalArcs(ctx) {
        const tgtX = convergePt.x;
        const tgtY = convergePt.y;
        for (const pop of RESOLVER_POPS) {
            const p = GC.projectPt(globe, pop.lat, pop.lon);
            if (!p.vis) continue;
            const cpx = p.x + (tgtX - p.x) * 0.5 + (p.y - tgtY) * 0.12;
            const cpy = p.y + (tgtY - p.y) * 0.5;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.quadraticCurveTo(cpx, cpy, tgtX, tgtY);
            ctx.strokeStyle = GC.hexToRgba(pop.color, 0.12 + p.depth * 0.06);
            ctx.lineWidth = 0.8;
            ctx.stroke();
        }
        for (const sp of signalParticles) {
            const pop2 = RESOLVER_POPS[sp.popIdx];
            const p2 = GC.projectPt(globe, pop2.lat, pop2.lon);
            if (!p2.vis) continue;
            const t = sp.t;
            const cpx2 = p2.x + (tgtX - p2.x) * 0.5 + (p2.y - tgtY) * 0.12;
            const cpy2 = p2.y + (tgtY - p2.y) * 0.5;
            const mt = 1 - t;
            const px = mt * mt * p2.x + 2 * mt * t * cpx2 + t * t * tgtX;
            const py = mt * mt * p2.y + 2 * mt * t * cpy2 + t * t * tgtY;
            ctx.beginPath();
            ctx.arc(px, py, sp.size, 0, Math.PI * 2);
            ctx.fillStyle = GC.hexToRgba(pop2.color, 0.5 + t * 0.3);
            ctx.fill();
            sp.t += sp.speed;
            if (sp.t > 1) { sp.t = 0; sp.speed = 0.003 + Math.random() * 0.004; sp.size = 1.5 + Math.random() * 1.5; }
        }
    }

    function drawResolverMarkers(ctx, w) { // NOSONAR
        const visiblePops = [];
        for (const [idx, pop] of RESOLVER_POPS.entries()) {
            const p = GC.projectPt(globe, pop.lat, pop.lon);
            if (p.vis) visiblePops.push({ pop: pop, p: p, idx: idx });
        }
        visiblePops.sort(function(a, b) { return a.p.depth - b.p.depth; });

        const SCL = Math.max(0.65, Math.min(1.15, w / 1400));
        const FONT_TAG = Math.round(Math.max(10, Math.min(15, 13 * SCL)));
        const labelGap = 12 * SCL;
        const labelBand = 120 * SCL;
        const placedBoxes = [];

        for (const vp of visiblePops) {
            const pop2 = vp.pop;
            const p2 = vp.p;
            const alpha = 0.4 + p2.depth * 0.6;
            ctx.beginPath(); ctx.arc(p2.x, p2.y, 7, 0, Math.PI * 2);
            ctx.fillStyle = GC.hexToRgba(pop2.color, 0.15 * alpha); ctx.fill();
            ctx.beginPath(); ctx.arc(p2.x, p2.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = GC.hexToRgba(pop2.color, 0.85 * alpha); ctx.fill();

            const label = pop2.city;
            ctx.font = FONT_TAG + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            const tw = ctx.measureText(label).width;
            const tagW = tw + 18 * SCL;
            const tagH = Math.round(20 * SCL + 2);

            const pos = GC.placeLabel({ dotX: p2.x, dotY: p2.y, tagW: tagW, tagH: tagH, globeCx: globe.cx, globeCy: globe.cy, globeR: globe.R, placedBoxes: placedBoxes, labelGap: labelGap, labelBand: labelBand });
            placedBoxes.push({ x: pos.x, y: pos.y, w: tagW, h: tagH });

            const lineEndX = (pos.x + tagW / 2 > p2.x) ? pos.x : pos.x + tagW;
            ctx.beginPath(); ctx.moveTo(p2.x, p2.y); ctx.lineTo(lineEndX, pos.y + tagH / 2);
            ctx.strokeStyle = GC.hexToRgba(pop2.color, 0.3 * alpha); ctx.lineWidth = 0.7; ctx.stroke();
            GC.roundRect(ctx, pos.x, pos.y, tagW, tagH, 4);
            ctx.fillStyle = 'rgba(0,0,0,' + (0.5 * alpha) + ')'; ctx.fill();
            GC.roundRect(ctx, pos.x, pos.y, tagW, tagH, 4);
            ctx.fillStyle = GC.hexToRgba(pop2.color, 0.55 * alpha); ctx.fill();
            ctx.strokeStyle = GC.hexToRgba(pop2.color, 0.7 * alpha); ctx.lineWidth = 0.8; ctx.stroke();
            ctx.fillStyle = 'rgba(255,255,255,' + (0.95 * alpha) + ')';
            ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
            ctx.fillText(label, pos.x + 9 * SCL, pos.y + tagH / 2);
        }

        for (const probe of OWN_PROBES) {
            const pp = GC.projectPt(globe, probe.lat, probe.lon);
            if (!pp.vis) continue;
            const pAlpha = 0.4 + pp.depth * 0.6;
            const now = performance.now();
            const pulse = 0.5 + 0.5 * Math.sin(now / 600);
            ctx.beginPath(); ctx.arc(pp.x, pp.y, 12, 0, Math.PI * 2);
            ctx.fillStyle = GC.hexToRgba(probe.color, 0.08 * pAlpha * pulse); ctx.fill();
            ctx.beginPath(); ctx.arc(pp.x, pp.y, 8, 0, Math.PI * 2);
            ctx.fillStyle = GC.hexToRgba(probe.color, 0.15 * pAlpha); ctx.fill();
            ctx.strokeStyle = GC.hexToRgba(probe.color, 0.5 * pAlpha); ctx.lineWidth = 1.2; ctx.stroke();
            ctx.save(); ctx.translate(pp.x, pp.y); ctx.rotate(Math.PI / 4);
            ctx.fillStyle = GC.hexToRgba(probe.color, 0.95 * pAlpha); ctx.fillRect(-3.5, -3.5, 7, 7); ctx.restore();

            const pLabel = probe.label;
            ctx.font = FONT_TAG + 'px -apple-system, BlinkMacSystemFont, sans-serif';
            const ptw = ctx.measureText(pLabel).width;
            const pTagW = ptw + 18 * SCL;
            const pTagH = Math.round(20 * SCL + 2);
            const pCandidateAngles = [0, 20, -20, 40, -40, 60, -60, 80, -80, 100, -100, 120, -120, 140, -140, 160, -160, 180];
            const pCandidateDists = [globe.R * 0.18 + labelGap, globe.R * 0.28 + labelGap, globe.R * 0.38 + labelGap];

            const pPos = GC.placeLabel({ dotX: pp.x, dotY: pp.y, tagW: pTagW, tagH: pTagH, globeCx: globe.cx, globeCy: globe.cy, globeR: globe.R, placedBoxes: placedBoxes, labelGap: labelGap, labelBand: labelBand, candidateAngles: pCandidateAngles, candidateDists: pCandidateDists });
            placedBoxes.push({ x: pPos.x, y: pPos.y, w: pTagW, h: pTagH });

            const pLineEndX = (pPos.x + pTagW / 2 > pp.x) ? pPos.x : pPos.x + pTagW;
            ctx.beginPath(); ctx.moveTo(pp.x, pp.y); ctx.lineTo(pLineEndX, pPos.y + pTagH / 2);
            ctx.strokeStyle = GC.hexToRgba(probe.color, 0.4 * pAlpha); ctx.lineWidth = 0.8; ctx.stroke();
            GC.roundRect(ctx, pPos.x, pPos.y, pTagW, pTagH, 4);
            ctx.fillStyle = 'rgba(0,0,0,' + (0.5 * pAlpha) + ')'; ctx.fill();
            GC.roundRect(ctx, pPos.x, pPos.y, pTagW, pTagH, 4);
            ctx.fillStyle = GC.hexToRgba(probe.color, 0.6 * pAlpha); ctx.fill();
            ctx.strokeStyle = GC.hexToRgba(probe.color, 0.8 * pAlpha); ctx.lineWidth = 1.0; ctx.stroke();
            ctx.fillStyle = 'rgba(255,255,255,' + (0.95 * pAlpha) + ')';
            ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
            ctx.fillText(pLabel, pPos.x + 9 * SCL, pPos.y + pTagH / 2);
        }
    }

    const PHI = 1.618033988749895;
    const VB_W = 900;
    const VB_H = 870;

    function renderGlobe(canvas) {
        const ctx = canvas.getContext('2d');
        let dpr = canvas._dpr || 1;
        let w = canvas._logW || canvas.width;
        const h = canvas._logH || canvas.height;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        const sc = Math.min(w / VB_W, h / VB_H);
        const offX = (w - VB_W * sc) / 2;
        const offY = (h - VB_H * sc) / 2;
        const maxR = 170 * sc;
        const foW = 900 * sc;
        const foH = 800 * sc;
        globe.R = Math.min(foW / (2 * PHI), foH / (2 * PHI), maxR);
        globe.cx = offX + 430 * sc;
        globe.cy = offY + 240 * sc;
        convergePt.x = offX + 430 * sc;
        convergePt.y = offY + 476 * sc;
        ctx.clearRect(0, 0, w, h);
        GC.drawGlobeSphere(ctx, globe);
        drawSignalArcs(ctx);
        drawResolverMarkers(ctx, w);
        ctx.setTransform(1, 0, 0, 1, 0, 0);
    }

    const rmq = globalThis.matchMedia('(prefers-reduced-motion: reduce)');

    function sizeCanvasToScreen(canvas) {
        const svg = canvas.parentNode?.querySelector('.topo-svg');
        if (!svg) return;
        const rect = svg.getBoundingClientRect();
        const rw = rect.width, rh = rect.height;
        if (rw < 10 || rh < 10) return;
        const dpr = globalThis.devicePixelRatio || 1;
        canvas.width = Math.round(rw * dpr);
        canvas.height = Math.round(rh * dpr);
        canvas._dpr = dpr;
        canvas._logW = rw;
        canvas._logH = rh;
    }

    let _sizeRetries = 0;
    function startGlobeAnimation() {
        if (_globeAnim) cancelAnimationFrame(_globeAnim);
        const canvas = document.querySelector('.topo-globe-canvas');
        if (!canvas) return;
        sizeCanvasToScreen(canvas);
        if (!canvas._logW || canvas._logW < 20 || !canvas._logH || canvas._logH < 20) {
            _sizeRetries++;
            if (_sizeRetries < 15) {
                const delay = Math.min(200, 40 * _sizeRetries);
                requestAnimationFrame(function() { setTimeout(startGlobeAnimation, delay); });
            }
            return;
        }
        _sizeRetries = 0;
        if (!particlesInitialized) { signalParticles = GC.initSignalParticles(RESOLVER_POPS); particlesInitialized = true; }
        const reduced = rmq.matches;
        renderGlobe(canvas);
        if (reduced) {
            if (!globe._texLoaded) {
                const waitTex = function() {
                    if (globe._texLoaded) { renderGlobe(canvas); return; }
                    setTimeout(waitTex, 200);
                };
                setTimeout(waitTex, 200);
            }
            return;
        }
        function tick() {
            globe.rotLon += 0.08;
            renderGlobe(canvas);
            _globeAnim = requestAnimationFrame(tick);
        }
        _globeAnim = requestAnimationFrame(tick);
    }

    let _globeStartTimer = null;
    const observer = new MutationObserver(function() {
        const topo = document.querySelector('.scan-topology');
        if (topo?.getAttribute('aria-hidden') === 'false') {
            if (_globeStartTimer) clearTimeout(_globeStartTimer);
            requestAnimationFrame(function() {
                _globeStartTimer = setTimeout(startGlobeAnimation, 80);
            });
        } else {
            if (_globeStartTimer) { clearTimeout(_globeStartTimer); _globeStartTimer = null; }
            stopGlobeAnimation();
        }
    });

    const topoEl = document.querySelector('.scan-topology');
    if (topoEl) {
        observer.observe(topoEl, { attributes: true, attributeFilter: ['aria-hidden'] });
        if (topoEl.getAttribute('aria-hidden') === 'false') {
            startGlobeAnimation();
        }
    }

    rmq.addEventListener('change', function() {
        const topo2 = document.querySelector('.scan-topology');
        if (topo2?.getAttribute('aria-hidden') === 'false') {
            startGlobeAnimation();
        }
    });

    globalThis._startGlobeAnimation = startGlobeAnimation;
    globalThis._stopGlobeAnimation = stopGlobeAnimation;
}

function initVideoFallback() {
    const csvEl = document.getElementById('caseStudyVideo');
    if (!csvEl) return;
    csvEl.addEventListener('error', function() {
        const w = csvEl.closest('.approach-video-wrapper');
        if (w) {
            const msg = document.createElement('div');
            msg.className = 'video-fallback-msg';
            msg.appendChild(document.createTextNode('Video could not load. '));
            var watchLink = document.createElement('a');
            watchLink.href = '/video/forgotten-domain';
            watchLink.textContent = 'Watch on dedicated page';
            msg.appendChild(watchLink);
            msg.appendChild(document.createTextNode(' or '));
            var dlLink = document.createElement('a');
            dlLink.href = '/static/video/forgotten-domain.mp4';
            dlLink.download = '';
            dlLink.textContent = 'download directly';
            msg.appendChild(dlLink);
            msg.appendChild(document.createTextNode('.'));
            csvEl.replaceWith(msg);
        }
    }, true);
    const src = csvEl.querySelector('source');
    if (src) {
        src.addEventListener('error', function() {
            csvEl.dispatchEvent(new Event('error'));
        });
    }
}

function initROEModal() {
    const roeModalEl = document.getElementById('roeModal');
    let roeModal = null;
    if (roeModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        roeModal = new bootstrap.Modal(roeModalEl);
        roeModalEl.addEventListener('show.bs.modal', function() { roeModalEl.removeAttribute('inert'); roeModalEl.removeAttribute('aria-hidden'); });
        roeModalEl.addEventListener('shown.bs.modal', function() { roeModalEl.removeAttribute('inert'); });
        roeModalEl.addEventListener('hidden.bs.modal', function() { roeModalEl.setAttribute('inert', ''); roeModalEl.setAttribute('aria-hidden', 'true'); });
    }
    let roeHandled = false;
    function handleRoeAccept(e) {
        if (roeHandled) return;
        roeHandled = true;
        setTimeout(function() { roeHandled = false; }, 400);
        if (e) { e.preventDefault(); }
        markROEAccepted();
        playMorseEasterEgg();
        if (roeModal) { roeModal.hide(); }
        activateCovertOrSwitch();
    }
    function handleRoeDecline(e) {
        if (roeHandled) return;
        roeHandled = true;
        setTimeout(function() { roeHandled = false; }, 400);
        if (e) { e.preventDefault(); }
        if (roeModal) { roeModal.hide(); }
        globalThis.location.href = 'https://youtu.be/7zUJ-dx2xXw?si=PBI0AoTgfPAellVW';
    }
    const roeAcceptBtn = document.getElementById('roeAccept');
    if (roeAcceptBtn) {
        roeAcceptBtn.addEventListener('click', handleRoeAccept);
        roeAcceptBtn.addEventListener('touchend', handleRoeAccept);
    }
    const roeDeclineBtn = document.getElementById('roeDecline');
    if (roeDeclineBtn) {
        roeDeclineBtn.addEventListener('click', handleRoeDecline);
        roeDeclineBtn.addEventListener('touchend', handleRoeDecline);
    }
    return roeModal;
}

function initCovertControls(roeModal) {
    const covertBtn = document.getElementById('covertToggle');
    if (covertBtn) {
        covertBtn.addEventListener('click', function() {
            if (document.body.classList.contains('covert-mode')) {
                const idEl = document.querySelector('[data-analysis-id]');
                if (idEl?.dataset.analysisId) {
                    const aid = idEl.dataset.analysisId;
                    setCovertMode(false);
                    const psMeta = document.querySelector('meta[name="x-public-suffix"]');
                    const exitView = (psMeta?.getAttribute('content') === '1') ? 'Z' : 'E';
                    saveScrollPosition();
                    globalThis.location.href = '/analysis/' + aid + '/view/' + exitView;
                    return;
                }
                setCovertMode(false);
                return;
            }
            if (!hasAcceptedROE() && roeModal) {
                roeModal.show();
                return;
            }
            playMorseEasterEgg();
            activateCovertOrSwitch();
        });
    }
    const covertExitHome = document.getElementById('covertExitHome');
    if (covertExitHome) {
        covertExitHome.addEventListener('click', function() {
            setCovertMode(false);
        });
    }
    initFullscreenControls();
    if (document.body.classList.contains('covert-mode')) {
        setCovertEnv(getCovertEnv());
        const initToggle = document.getElementById('covertToggle');
        if (initToggle) { initToggle.setAttribute('aria-pressed', 'true'); }
    }
}

function initFullscreenControls() {
    document.addEventListener('click', function(e) {
        const envBtn = e.target.closest('.covert-env-btn');
        if (envBtn?.dataset?.env) {
            setCovertEnv(envBtn.dataset.env);
        }
        const fsBtn = e.target.closest('.covert-fullscreen-btn');
        if (fsBtn) {
            const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
            if (fsEl) {
                if (document.exitFullscreen) { document.exitFullscreen(); }
                else if (document.webkitExitFullscreen) { document.webkitExitFullscreen(); }
            } else {
                const de = document.documentElement;
                if (de.requestFullscreen) { de.requestFullscreen({ navigationUI: 'hide' }); }
                else if (de.webkitRequestFullscreen) { de.webkitRequestFullscreen(); }
            }
        }
    });
    function handleFullscreenChange() {
        const fsEl = document.fullscreenElement || document.webkitFullscreenElement;
        for (const b of document.querySelectorAll('.covert-fullscreen-btn')) {
            const ic = b.querySelector('.icon');
            if (fsEl) {
                if (ic && globalThis._icons) { ic.replaceWith(parseIcon(globalThis._icons.compress)); }
                b.setAttribute('title', 'Exit Focus Mode (Esc)');
            } else {
                if (ic && globalThis._icons) { ic.replaceWith(parseIcon(globalThis._icons.expand)); }
                b.setAttribute('title', 'Focus Mode — hide browser chrome for full scotopic immersion');
            }
        }
    }
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
    const fsSupported = document.fullscreenEnabled || document.webkitFullscreenEnabled || false;
    if (!fsSupported) {
        for (const b of document.querySelectorAll('.covert-fullscreen-btn')) {
            b.classList.add('d-none');
        }
    }
}

function restoreScrollPosition() {
    try {
        const savedY = sessionStorage.getItem('covert_scroll_y');
        if (savedY !== null) {
            sessionStorage.removeItem('covert_scroll_y');
            const y = Number.parseInt(savedY, 10);
            if (!Number.isNaN(y) && y > 0) { globalThis.scrollTo(0, y); }
        }
    } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function initSmoothScroll() {
    for (const anchor of document.querySelectorAll('a[href^="#"]')) {
        anchor.addEventListener('click', function(e) {
            if (('bsToggle' in this.dataset)) return;
            e.preventDefault();
            const href = this.getAttribute('href');
            if (!href || href === '#') return;
            try {
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            } catch(_e) { /* invalid selector */ } // NOSONAR
        });
    }
}

function initAlertDismissal() {
    for (const alert of document.querySelectorAll('.alert-dismissible:not(.alert-persistent)')) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    }

    for (const btn of document.querySelectorAll('.alert-dismissible .btn-close')) {
        btn.addEventListener('click', function() {
            const alertEl = btn.closest('.alert');
            if (alertEl) {
                try {
                    const bsAlert = bootstrap.Alert.getOrCreateInstance(alertEl);
                    bsAlert.close();
                } catch (e) {
                    console.warn('Bootstrap alert fallback:', e.message);
                    alertEl.classList.remove('show');
                    alertEl.addEventListener('transitionend', function() { alertEl.remove(); });
                    setTimeout(function() { alertEl.remove(); }, 300);
                }
            }
        });
    }
}

function initCodeBlocks() {
    for (const codeBlock of document.querySelectorAll('.code-block')) {
        codeBlock.classList.add('u-pointer');
        codeBlock.title = 'Click to copy';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.ariaLabel = 'Copy to clipboard';
        btn.appendChild(parseIcon(globalThis._icons.copy));
        codeBlock.appendChild(btn);

        const doCopy = createCopyHandler(codeBlock, btn);
        btn.addEventListener('click', doCopy);
        codeBlock.addEventListener('click', doCopy);
    }
}

function initDomainForm() {
    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');

    if (!domainForm || !domainInput || !analyzeBtn) return;

    domainInput.addEventListener('input', function() {
        const domain = this.value.trim();
        const isValid = domain === '' || isValidDomain(domain);

        if (domain && !isValid) {
            this.classList.add('is-invalid');
            analyzeBtn.disabled = true;
        } else {
            this.classList.remove('is-invalid');
            analyzeBtn.disabled = false;
        }
    });

    if (globalThis.innerWidth >= 768 && !('ontouchstart' in globalThis)) {
        domainInput.focus();
    }

    let analysisSubmitted = false;
    domainForm.addEventListener('submit', function(e) {
        if (analysisSubmitted) return;
        e.preventDefault();
        const covertField = document.getElementById('covertField');
        if (covertField) {
            const isCovert = document.body.classList.contains('covert-mode') ? '1' : '0';
            covertField.value = isCovert;
        }
        const domain = domainInput.value.trim().toLowerCase().replace(/^\./, '');
        domainInput.value = domain;

        if (!domain) {
            domainInput.classList.add('is-invalid');
            return;
        }

        if (!isValidDomain(domain)) {
            domainInput.classList.add('is-invalid');
            return;
        }

        if (!domainForm.checkValidity()) {
            domainForm.reportValidity();
            return;
        }

        if (document.body.classList.contains('covert-mode') && isBareTopLevelDomain(domain)) {
            showCovertTLDToast(domain);
        }

        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            const domainEl = overlay.querySelector('.scan-overlay-domain');
            if (domainEl) {
                domainEl.textContent = domain;
            }
            if (isBareTopLevelDomain(domain)) {
                swapToTLDScanPhases(overlay);
            }
            showOverlay(overlay);
            startStatusCycle(overlay);
        }
        setIconAndText(analyzeBtn, globalThis._icons?.spinner ?? null, ' Analyzing...');
        analyzeBtn.disabled = true;
        document.body.classList.add('loading');
        analysisSubmitted = true;
        const formData = new FormData(domainForm);
        fetch(domainForm.action, {
            method: 'POST',
            body: formData,
            headers: { 'X-Requested-With': 'fetch', 'Accept': 'application/json' },
            redirect: 'follow'
        }).then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        }).then(function(data) {
            if (data.token) {
                startProgressPolling(data.token, overlay, analyzeBtn);
            }
        }).catch(function() {
            hideOverlayAndReset(overlay, analyzeBtn);
            analysisSubmitted = false;
            const flash = document.createElement('div');
            flash.className = 'alert alert-danger alert-dismissible fade show mt-3';
            flash.role = 'alert';
            flash.textContent = 'Network error \u2014 please check your connection and try again.';
            const closeBtn = document.createElement('button');
            closeBtn.type = 'button';
            closeBtn.className = 'btn-close';
            closeBtn.dataset.bsDismiss = 'alert';
            flash.appendChild(closeBtn);
            domainForm.parentNode.insertBefore(flash, domainForm);
        });
    });

    domainInput.addEventListener('focus', function() {
        this.classList.remove('is-invalid');
    });
}

document.addEventListener('DOMContentLoaded', function() {
    restoreScrollPosition();
    document.addEventListener('click', function() { _ensureMorseAudio(); }, { once: true });
    initGlobeMotion();
    initVideoFallback();
    initPrivacyToggle();
    const roeModal = initROEModal();
    initCovertControls(roeModal);
    initPrivacyBanner();
    initDomainForm();

    for (const link of document.querySelectorAll('a[href^="/analyze?domain="]')) {
        if (link.id === 'reanalyzeBtn') continue;
        if (link.classList.contains('history-reanalyze-btn')) continue;
        link.addEventListener('click', handleAnalyzeLinkClick);
    }

    document.addEventListener('click', function(e) {
        let btn = e.target.closest('#reanalyzeBtn');
        if (!btn || btn.classList.contains('disabled')) return;
        e.preventDefault();
        let domain = btn.dataset.domain;
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            const domainEl = overlay.querySelector('.scan-overlay-domain');
            if (domainEl) domainEl.textContent = domain;
            if (typeof isBareTopLevelDomain === 'function' && isBareTopLevelDomain(domain)) {
                swapToTLDScanPhases(overlay);
            }
            showOverlay(overlay);
            startStatusCycle(overlay);
        }
        while (btn.firstChild) btn.removeChild(btn.firstChild);
        var spinIcon = document.createElement('i');
        spinIcon.className = 'fa-solid fa-spinner icon-spin me-2';
        btn.appendChild(spinIcon);
        btn.appendChild(document.createTextNode('Analyzing...'));
        btn.classList.add('disabled');
        document.body.classList.add('loading');
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content ?? '';
        const isCovert = document.body.classList.contains('covert-mode');
        let body = new URLSearchParams({domain: domain, csrf_token: csrf});
        if (isCovert) body.append('covert', '1');
        fetch('/analyze', {
            method: 'POST',
            body: body,
            headers: {'X-Requested-With': 'fetch', 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'},
            redirect: 'follow'
        }).then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        }).then(function(data) {
            if (data.token) {
                startProgressPolling(data.token, overlay, btn);
            }
        }).catch(function() {
            performFallbackAnalysis(domain, isCovert, overlay, btn);
        });
    });

    initAlertDismissal();
    initSmoothScroll();
    initCodeBlocks();
});

const allFixesCollapse = document.getElementById('allFixesCollapse');
if (allFixesCollapse) {
    const toggleBtn = document.querySelector('[data-bs-target="#allFixesCollapse"]');
    if (toggleBtn) {
        const originalNodes = Array.from(toggleBtn.childNodes).map(function(node) {
            return node.cloneNode(true);
        });
        allFixesCollapse.addEventListener('shown.bs.collapse', function() {
            setIconAndText(toggleBtn, globalThis._icons?.chevronUp ?? null, ' Show fewer');
        });
        allFixesCollapse.addEventListener('hidden.bs.collapse', function() {
            toggleBtn.textContent = '';
            for (const node of originalNodes) {
                toggleBtn.appendChild(node.cloneNode(true));
            }
        });
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function createHistoryRow(ch) {
    let typeColor = 'secondary';
    if (ch.record_type === 'A' || ch.record_type === 'AAAA') {
        typeColor = 'primary';
    } else if (ch.record_type === 'MX') {
        typeColor = 'success';
    } else if (ch.record_type === 'NS') {
        typeColor = 'info';
    }
    const tr = document.createElement('tr');

    const tdDate = document.createElement('td');
    const codeDate = document.createElement('code');
    codeDate.className = 'text-muted u-fs-080em';
    codeDate.textContent = ch.date || '';
    tdDate.appendChild(codeDate);

    const tdType = document.createElement('td');
    const badgeType = document.createElement('span');
    badgeType.className = 'badge bg-' + typeColor;
    badgeType.textContent = ch.record_type || '';
    tdType.appendChild(badgeType);

    const tdAction = document.createElement('td');
    const actionSpan = document.createElement('span');
    if (ch.action === 'added') {
        actionSpan.className = 'text-success';
        setIconAndText(actionSpan, globalThis._icons?.plusCircle ?? null, ' Added');
    } else {
        actionSpan.className = 'text-danger';
        setIconAndText(actionSpan, globalThis._icons?.minusCircle ?? null, ' Removed');
    }
    tdAction.appendChild(actionSpan);

    const tdValue = document.createElement('td');
    const codeValue = document.createElement('code');
    codeValue.className = 'u-fs-085em';
    codeValue.textContent = ch.value || '';
    tdValue.appendChild(codeValue);

    const tdOrg = document.createElement('td');
    const spanOrg = document.createElement('span');
    spanOrg.className = 'text-muted';
    spanOrg.textContent = ch.org || '\u2014';
    tdOrg.appendChild(spanOrg);

    const tdDesc = document.createElement('td');
    const spanDesc = document.createElement('span');
    spanDesc.className = 'text-muted u-fs-085em';
    spanDesc.textContent = ch.description || '';
    tdDesc.appendChild(spanDesc);

    tr.appendChild(tdDate);
    tr.appendChild(tdType);
    tr.appendChild(tdAction);
    tr.appendChild(tdValue);
    tr.appendChild(tdOrg);
    tr.appendChild(tdDesc);
    return tr;
}

function loadDNSHistory(domain) {
    const btn = document.getElementById('dns-history-btn');
    if (!btn) return;
    btn.disabled = true;
    setIconAndText(btn, globalThis._icons?.spinner ?? null, ' Loading history\u2026');

    fetch('/api/dns-history?domain=' + encodeURIComponent(domain))
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (!data || data.status === 'unavailable' || data.status === 'error' || !data.available) {
                btn.closest('.dns-history-load-wrapper').classList.add('d-none');
                return;
            }
            const section = document.getElementById('dns-history-section');
            const body = document.getElementById('dns-history-body');
            const source = document.getElementById('dns-history-source');
            if (!section || !body) return;

            source.textContent = 'Source: ' + (data.source || 'SecurityTrails');

            const changes = data.changes || [];
            body.textContent = '';
            if (changes.length === 0) {
                const p = document.createElement('p');
                p.className = 'text-muted mb-0';
                setIconAndText(p, globalThis._icons?.checkCircle ?? null, ' No DNS record changes detected in available history. A, AAAA, MX, and NS records for this domain have remained stable.');
                body.appendChild(p);
            } else {
                const wrap = document.createElement('div');
                wrap.className = 'table-responsive';
                const table = document.createElement('table');
                table.className = 'table table-sm table-striped mb-0';
                const thead = document.createElement('thead');
                const headRow = document.createElement('tr');
                const headers = [
                    {text: 'Date', cls: 'u-w-80px'}, {text: 'Type', cls: 'u-w-60px'},
                    {text: 'Action', cls: 'u-w-70px'}, {text: 'Value'}, {text: 'Organization'}, {text: 'Timeline'}
                ];
                for (const h of headers) {
                    const th = document.createElement('th');
                    if (h.cls) th.className = h.cls;
                    th.textContent = h.text;
                    headRow.appendChild(th);
                }
                thead.appendChild(headRow);
                table.appendChild(thead);
                const tbody = document.createElement('tbody');
                for (const ch of changes) {
                    tbody.appendChild(createHistoryRow(ch));
                }
                table.appendChild(tbody);
                wrap.appendChild(table);
                body.appendChild(wrap);
            }

            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
            section.classList.remove('d-none');
        })
        .catch(function() {
            btn.closest('.dns-history-load-wrapper').classList.add('d-none');
        });
}

function rfcFallbackOverlay(url) {
    try { var u = new URL(url, location.href); if (u.protocol !== 'https:' && u.protocol !== 'http:') return; } catch(e) { return; }
    var existing = document.getElementById('rfcFallbackOverlay');
    if (existing) existing.remove();
    var rfcMatch = url.match(/rfc(\d+)\.html/);
    var rfcNum = rfcMatch ? rfcMatch[1] : '';
    var sectionMatch = url.match(/#section-([\d.]+)/);
    var sectionLabel = sectionMatch ? ' \u00a7' + sectionMatch[1] : '';
    var backdrop = document.createElement('div');
    backdrop.id = 'rfcFallbackOverlay';
    backdrop.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center';
    var card = document.createElement('div');
    card.style.cssText = 'background:#1a1a2e;color:#e0e0e0;border-radius:12px;padding:28px 32px;max-width:420px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.5);text-align:center;font-family:system-ui,sans-serif';
    var titleDiv = document.createElement('div');
    titleDiv.style.cssText = 'font-size:1.5rem;font-weight:700;margin-bottom:8px';
    titleDiv.textContent = 'RFC ' + rfcNum + sectionLabel;
    var desc = document.createElement('p');
    desc.style.cssText = 'margin:12px 0;color:#aaa;font-size:.9rem';
    desc.textContent = 'Your browser blocked the popup window. Open this RFC directly:';
    var link = document.createElement('a');
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.style.cssText = 'display:inline-block;margin:12px 0;padding:10px 28px;background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;font-weight:600';
    link.textContent = 'Open RFC' + (rfcNum ? ' ' + rfcNum : '');
    var closeDiv = document.createElement('div');
    closeDiv.style.cssText = 'margin-top:16px';
    var closeBtn = document.createElement('button');
    closeBtn.style.cssText = 'background:none;border:1px solid #555;color:#aaa;padding:6px 18px;border-radius:6px;cursor:pointer;font-size:.85rem';
    closeBtn.id = 'rfcFallbackClose';
    closeBtn.textContent = 'Close';
    closeDiv.appendChild(closeBtn);
    card.appendChild(titleDiv);
    card.appendChild(desc);
    card.appendChild(link);
    card.appendChild(closeDiv);
    backdrop.appendChild(card);
    document.body.appendChild(backdrop);
    backdrop.addEventListener('click', function(ev) {
        if (ev.target === backdrop || ev.target.id === 'rfcFallbackClose') backdrop.remove();
    });
    document.addEventListener('keydown', function onEsc(ev) {
        if (ev.key === 'Escape') { backdrop.remove(); document.removeEventListener('keydown', onEsc); }
    });
}

function openRFCPopup(url, evt) {
    if (evt) { evt.preventDefault(); evt.stopPropagation(); }
    var w = 720, h = 520;
    var left = (screen.width - w) / 2;
    var top = (screen.height - h) / 2;
    var win = window.open(url, 'rfcPopup',
        'width=' + w + ',height=' + h + ',left=' + left + ',top=' + top +
        ',scrollbars=yes,resizable=yes,menubar=no,toolbar=no,location=yes,status=no,noopener,noreferrer');
    if (win) { win.opener = null; } else { rfcFallbackOverlay(url); }
}

document.addEventListener('click', function(e) {
    if (e.defaultPrevented) return;
    var link = e.target.closest('a[href*="rfc-editor.org/rfc/rfc"]');
    if (!link) return;
    openRFCPopup(link.href, e);
});

globalThis.showOverlay = showOverlay;
globalThis.startStatusCycle = startStatusCycle;
globalThis.startProgressPolling = startProgressPolling;
globalThis.hideOverlayAndReset = hideOverlayAndReset;
globalThis.escapeHtml = escapeHtml;
globalThis.loadDNSHistory = loadDNSHistory;
globalThis.openRFCPopup = openRFCPopup;

})();
