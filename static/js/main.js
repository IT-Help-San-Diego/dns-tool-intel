(function() {
    if (document.documentElement.classList.contains('covert-mode')) {
        document.body.classList.add('covert-mode');
        try {
            const env = localStorage.getItem('covertEnv') || 'tactical';
            document.body.classList.add('covert-' + env);
        } catch(_e) { /* localStorage unavailable — fall back to tactical */ // NOSONAR
            document.body.classList.add('covert-tactical');
        }
    }
})();

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(function() { /* intentionally empty — SW optional */ }); // NOSONAR
}

globalThis.addEventListener('pageshow', function(e) {
    if (e.persisted) {
        document.querySelectorAll('.loading-overlay').forEach(function(overlay) {
            overlay.classList.remove('is-active');
            if (overlay.dataset.timerId) {
                clearInterval(Number(overlay.dataset.timerId));
                delete overlay.dataset.timerId;
            }
        });
        document.body.classList.remove('loading');
        const reanalyzeBtn = document.getElementById('reanalyzeBtn');
        if (reanalyzeBtn && !reanalyzeBtn.classList.contains('disabled')) {
            reanalyzeBtn.innerHTML = '<i class="fas fa-sync-alt me-2"></i>Re-analyze';
        }
        const analyzeBtn = document.getElementById('analyzeBtn');
        if (analyzeBtn) {
            analyzeBtn.innerHTML = '<i class="fas fa-search me-1"></i> Analyze';
            analyzeBtn.disabled = false;
        }
        document.querySelectorAll('.history-view-btn,.history-reanalyze-btn').forEach(function(b) {
            b.classList.remove('disabled');
            b.removeAttribute('aria-disabled');
        });
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
 * NEVER use location.href or window.location to start a scan that
 * depends on an active overlay timer. See index.html and history.html
 * for reference implementations.
 */
function showOverlay(overlay) {
    if (!overlay) return;
    overlay.classList.add('is-active');
    requestAnimationFrame(function() {
        requestAnimationFrame(function() {
            for (const el of overlay.querySelectorAll('.loading-spinner, .loading-spinner i, .loading-dots span')) {
                const anim = getComputedStyle(el).animationName;
                if (anim && anim !== 'none') {
                    el.classList.add('anim-restart');
                    void el.offsetWidth; // NOSONAR — Safari reflow
                    el.classList.remove('anim-restart');
                }
            }
        });
    });
}

function startStatusCycle(overlayEl) {
    const timerEl = document.getElementById('loadingTimer') || overlayEl.querySelector('.loading-elapsed span');
    const noteEl = document.getElementById('loadingNote');
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

    const phases = overlayEl.querySelectorAll('.scan-phase');
    if (phases.length === 0) return;

    let completed = 0;
    phases.forEach(function(phase, idx) {
        const delay = Number.parseInt(phase.dataset.delay, 10) || 0;
        setTimeout(function() {
            phase.classList.add('visible', 'active-phase');
        }, delay);

        const doneDelay = delay + 1800 + Math.random() * 1200; // NOSONAR — animation timing, not cryptographic
        if (idx === phases.length - 1) {
            return;
        }
        setTimeout(function() {
            phase.classList.remove('active-phase');
            phase.classList.add('done');
            const icon = phase.querySelector('.scan-icon');
            if (icon) {
                icon.classList.remove('fa-circle-notch', 'fa-spin', 'scan-pending');
                void icon.offsetWidth; // NOSONAR — Safari reflow trigger for ::before content swap
                icon.classList.add('fa-check-circle');
            }
            completed++;
        }, doneDelay);
    });
}

function hideOverlayAndReset(overlay, btn) {
    if (overlay) {
        overlay.classList.remove('is-active');
        if (overlay.dataset.timerId) {
            clearInterval(Number(overlay.dataset.timerId));
            delete overlay.dataset.timerId;
        }
    }
    document.body.classList.remove('loading');
    if (btn) {
        btn.innerHTML = '<i class="fas fa-search me-1"></i> Analyze';
        btn.disabled = false;
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
    const checklist = overlay.querySelector('#scanChecklist');
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
    checklist.innerHTML = '';
    phases.forEach(function(p) {
        const div = document.createElement('div');
        div.className = 'scan-phase';
        div.dataset.delay = p.delay;
        const icon = document.createElement('i');
        icon.className = 'fas fa-circle-notch fa-spin scan-icon scan-pending';
        icon.setAttribute('aria-hidden', 'true');
        const span = document.createElement('span');
        span.className = isCovert ? 'covert-show' : 'covert-hide';
        span.textContent = isCovert ? p.covert : p.normal;
        div.appendChild(icon);
        div.appendChild(span);
        checklist.appendChild(div);
    });
}

function showCovertTLDToast(domain, callback) {
    const existing = document.getElementById('tldReconToast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.id = 'tldReconToast';
    toast.role = 'alert';
    toast.ariaLive = 'assertive';
    toast.className = 'tld-recon-toast';
    toast.innerHTML = '<div class="tld-recon-toast-title">'
        + '<i class="fas fa-globe-americas"></i>'
        + 'Planning to hack the planet, Zero Cool?</div>'
        + '<div class="tld-recon-toast-body">'
        + 'Bare\u2011TLD recon maps registry infrastructure only \u2014 '
        + 'DNSSEC, NS delegation, CAA, registrar, Nmap, SVCB. '
        + 'No SPF/DKIM/DMARC at zone scope.</div>'
        + '<div class="tld-recon-toast-footer">'
        + '<i class="fas fa-satellite-dish"></i>'
        + '</div>';
    const toastFooter = toast.querySelector('.tld-recon-toast-footer');
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
    let d = domain;
    while (d.charAt(0) === '.') d = d.slice(1);
    while (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
    if (d.length > 253 || d.length === 0) return false;
    const labels = d.split('.');
    if (labels.length === 1) {
        return /^[a-zA-Z]{2,}$/.test(labels[0]) || labels[0].startsWith('xn--');
    }
    for (const label of labels) {
        if (label.length === 0 || label.length > 63) return false;
        if (label.startsWith('-') || label.endsWith('-')) return false;
    }
    const lastLabel = labels[labels.length - 1];
    if (/^\d+$/.test(lastLabel)) return false;
    const hasNonAscii = /[^\u0020-\u007F]/.test(d);
    if (!hasNonAscii) {
        for (const label of labels) {
            if (!/^[a-zA-Z0-9-]+$/.test(label)) return false;
        }
    }
    return true;
}

function fetchAndApplyPage(url, options, overlay, btn) {
    return fetch(url, options).then(function(resp) {
        return resp.text().then(function(html) { applyFetchedPage(html, resp.url, overlay, btn); });
    });
}

function applyFetchedPage(html, respUrl, overlay, btn) {
    hideOverlayAndReset(overlay, btn);
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    document.replaceChild(
        document.importNode(parsed.documentElement, true),
        document.documentElement
    );
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
    btn.innerHTML = '<i class="fas fa-copy"></i>';
    btn.classList.remove('copied');
}

function handleCopyResult(btn, success) {
    btn.innerHTML = success ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>';
    if (success) btn.classList.add('copied');
    setTimeout(function() { resetCopyBtn(btn); }, 1500);
}

function createCopyHandler(codeBlock, btn) {
    return function(e) {
        e.stopPropagation();
        let copyText = '';
        codeBlock.childNodes.forEach(function(node) {
            if (node !== btn && !node.classList?.contains('copy-btn')) {
                copyText += node.textContent;
            }
        });
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
    covertEnvClasses.forEach(function(c) { document.body.classList.remove(c); });
}

function getCovertEnv() {
    try { return localStorage.getItem('covertEnv') || 'tactical'; } catch(_e) { return 'tactical'; } // NOSONAR
}

function hasAcceptedROE() {
    try { return localStorage.getItem('roeAccepted') === '1'; } catch(_e) { return false; } // NOSONAR
}

function markROEAccepted() {
    try { localStorage.setItem('roeAccepted', '1'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function playMorseEasterEgg() {
    try {
        const a = new Audio('/static/audio/morse-hack-the-planet.m4a');
        a.volume = 0.4;
        a.play().catch(function() { /* intentionally empty — autoplay may be blocked by browser policy */ }); // NOSONAR
    } catch(_e) { /* intentionally empty — Audio API unavailable in some contexts */ } // NOSONAR
}

function updateEnvButtons(env) {
    const btns = document.querySelectorAll('.covert-env-btn');
    btns.forEach(function(b) {
        b.classList.toggle('active', b.dataset.env === env);
    });
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
}

function setCovertMode(active) {
    if (active) {
        document.body.classList.add('covert-mode');
        setCovertEnv(getCovertEnv());
    } else {
        document.body.classList.remove('covert-mode');
        clearCovertEnv();
    }
    try { localStorage.setItem('covertMode', active ? '1' : '0'); } catch(_e) { /* storage unavailable */ } // NOSONAR
}

function activateCovertOrSwitch() {
    const idEl = document.querySelector('[data-analysis-id]');
    const modeMeta = document.querySelector('meta[name="x-report-mode"]');
    if (idEl && modeMeta) {
        const aid = idEl.dataset.analysisId;
        const cur = (modeMeta.getAttribute('content') || 'E').toUpperCase();
        if (aid && (cur === 'E' || cur === 'C')) {
            const target = cur === 'E' ? 'C' : 'E';
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
    const loadingDomain = document.getElementById('loadingDomain');
    const url = new URL(link.href, globalThis.location.origin);
    const domain = url.searchParams.get('domain') || '';
    if (overlay) {
        if (loadingDomain) loadingDomain.textContent = domain;
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

document.addEventListener('DOMContentLoaded', function() {
    const roeModalEl = document.getElementById('roeModal');
    let roeModal = null;
    if (roeModalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
        roeModal = new bootstrap.Modal(roeModalEl);
    }
    const roeAcceptBtn = document.getElementById('roeAccept');
    if (roeAcceptBtn) {
        roeAcceptBtn.addEventListener('click', function() {
            markROEAccepted();
            playMorseEasterEgg();
            if (roeModal) { roeModal.hide(); }
            activateCovertOrSwitch();
        });
    }
    const roeDeclineBtn = document.getElementById('roeDecline');
    if (roeDeclineBtn) {
        roeDeclineBtn.addEventListener('click', function() {
            if (roeModal) { roeModal.hide(); }
        });
    }
    const covertBtn = document.getElementById('covertToggle');
    if (covertBtn) {
        covertBtn.addEventListener('click', function() {
            if (document.body.classList.contains('covert-mode')) {
                setCovertMode(false);
                return;
            }
            if (!hasAcceptedROE() && roeModal) {
                roeModal.show();
                return;
            }
            activateCovertOrSwitch();
        });
    }
    const covertExitHome = document.getElementById('covertExitHome');
    if (covertExitHome) {
        covertExitHome.addEventListener('click', function() {
            setCovertMode(false);
        });
    }
    document.addEventListener('click', function(e) {
        const btn = e.target.closest('.covert-env-btn');
        if (btn?.dataset?.env) {
            setCovertEnv(btn.dataset.env);
        }
    });
    if (document.body.classList.contains('covert-mode')) {
        setCovertEnv(getCovertEnv());
    }

    const domainForm = document.getElementById('domainForm');
    const domainInput = document.getElementById('domain');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    if (domainForm && domainInput && analyzeBtn) {
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
            const loadingDomain = document.getElementById('loadingDomain');
            if (overlay) {
                if (loadingDomain) {
                    loadingDomain.textContent = domain;
                }
                if (isBareTopLevelDomain(domain)) {
                    swapToTLDScanPhases(overlay);
                }
                showOverlay(overlay);
                startStatusCycle(overlay);
            }
            analyzeBtn.textContent = '';
            const spinner = document.createElement('i');
            spinner.className = 'fas fa-spinner fa-spin me-2';
            analyzeBtn.appendChild(spinner);
            analyzeBtn.appendChild(document.createTextNode('Analyzing...'));
            analyzeBtn.disabled = true;
            document.body.classList.add('loading');
            analysisSubmitted = true;
            const formData = new FormData(domainForm);
            fetchAndApplyPage(domainForm.action, {
                method: 'POST',
                body: formData,
                headers: { 'X-Requested-With': 'fetch' },
                redirect: 'follow'
            }, overlay, analyzeBtn).catch(function() {
                hideOverlayAndReset(overlay, analyzeBtn);
                analysisSubmitted = false;
                const flash = document.createElement('div');
                flash.className = 'alert alert-danger alert-dismissible fade show mt-3';
                flash.role = 'alert';
                flash.textContent = 'Network error — please check your connection and try again.';
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
    
    document.querySelectorAll('a[href^="/analyze?domain="]').forEach(function(link) {
        if (link.id === 'reanalyzeBtn') return;
        if (link.classList.contains('history-reanalyze-btn')) return;
        link.addEventListener('click', handleAnalyzeLinkClick);
    });

    document.querySelectorAll('.alert-dismissible:not(.alert-persistent)').forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bsAlert.close();
        }, 5000);
    });

    document.querySelectorAll('.alert-dismissible .btn-close').forEach(function(btn) {
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
    });
    
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    document.querySelectorAll('.code-block').forEach(function(codeBlock) {
        codeBlock.classList.add('u-pointer');
        codeBlock.title = 'Click to copy';

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copy-btn';
        btn.ariaLabel = 'Copy to clipboard';
        btn.innerHTML = '<i class="fas fa-copy"></i>';
        codeBlock.appendChild(btn);

        const doCopy = createCopyHandler(codeBlock, btn);
        btn.addEventListener('click', doCopy);
        codeBlock.addEventListener('click', doCopy);
    });
});

const allFixesCollapse = document.getElementById('allFixesCollapse');
if (allFixesCollapse) {
    const toggleBtn = document.querySelector('[data-bs-target="#allFixesCollapse"]');
    if (toggleBtn) {
        const originalNodes = Array.from(toggleBtn.childNodes).map(function(node) {
            return node.cloneNode(true);
        });
        allFixesCollapse.addEventListener('shown.bs.collapse', function() {
            toggleBtn.textContent = '';
            const icon = document.createElement('i');
            icon.className = 'fas fa-chevron-up me-1';
            toggleBtn.appendChild(icon);
            toggleBtn.appendChild(document.createTextNode('Show fewer'));
        });
        allFixesCollapse.addEventListener('hidden.bs.collapse', function() {
            toggleBtn.textContent = '';
            originalNodes.forEach(function(node) {
                toggleBtn.appendChild(node.cloneNode(true));
            });
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
    const actionIcon = document.createElement('i');
    if (ch.action === 'added') {
        actionSpan.className = 'text-success';
        actionIcon.className = 'fas fa-plus-circle me-1';
        actionSpan.appendChild(actionIcon);
        actionSpan.appendChild(document.createTextNode('Added'));
    } else {
        actionSpan.className = 'text-danger';
        actionIcon.className = 'fas fa-minus-circle me-1';
        actionSpan.appendChild(actionIcon);
        actionSpan.appendChild(document.createTextNode('Removed'));
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
    btn.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Loading history\u2026';

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
                const ico = document.createElement('i');
                ico.className = 'fas fa-check-circle text-success me-1';
                p.appendChild(ico);
                p.appendChild(document.createTextNode('No DNS record changes detected in available history. A, AAAA, MX, and NS records for this domain have remained stable.'));
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
                headers.forEach(function(h) {
                    const th = document.createElement('th');
                    if (h.cls) th.className = h.cls;
                    th.textContent = h.text;
                    headRow.appendChild(th);
                });
                thead.appendChild(headRow);
                table.appendChild(thead);
                const tbody = document.createElement('tbody');
                changes.forEach(function(ch) {
                    tbody.appendChild(createHistoryRow(ch));
                });
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
