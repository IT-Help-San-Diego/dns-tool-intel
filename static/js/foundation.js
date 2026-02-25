(function() {
    'use strict';

    /* ── Collapse ── */
    function toggleCollapse(target) {
        if (!target) return;
        const isShown = target.classList.contains('show');
        if (isShown) {
            target.style.height = target.scrollHeight + 'px';
            void target.offsetHeight;
            target.style.height = '0';
            target.classList.add('collapsing');
            target.classList.remove('collapse', 'show');
            setTimeout(function() {
                target.classList.remove('collapsing');
                target.classList.add('collapse');
                target.style.height = '';
            }, 300);
        } else {
            target.classList.remove('collapse');
            target.classList.add('collapsing');
            target.style.height = '0';
            void target.offsetHeight;
            target.style.height = target.scrollHeight + 'px';
            setTimeout(function() {
                target.classList.remove('collapsing');
                target.classList.add('collapse', 'show');
                target.style.height = '';
            }, 300);
        }
        const triggers = document.querySelectorAll('[data-bs-target="#' + target.id + '"]');
        for (let i = 0; i < triggers.length; i++) {
            triggers[i].setAttribute('aria-expanded', String(!isShown));
            if (!isShown) {
                triggers[i].classList.remove('collapsed');
            } else {
                triggers[i].classList.add('collapsed');
            }
        }
    }

    document.addEventListener('click', function(e) {
        const trigger = e.target.closest('[data-bs-toggle="collapse"]');
        if (!trigger) return;
        e.preventDefault();
        const selector = trigger.getAttribute('data-bs-target');
        if (!selector) return;
        const target = document.querySelector(selector);
        toggleCollapse(target);
    });

    /* ── Dropdown ── */
    function closeAllDropdowns(except) {
        const openMenus = document.querySelectorAll('.dropdown-menu.show');
        for (let i = 0; i < openMenus.length; i++) {
            if (except && openMenus[i] === except) continue;
            openMenus[i].classList.remove('show');
            const parent = openMenus[i].closest('.dropdown');
            if (parent) {
                const toggle = parent.querySelector('[data-bs-toggle="dropdown"]');
                if (toggle) toggle.setAttribute('aria-expanded', 'false');
            }
        }
    }

    document.addEventListener('click', function(e) {
        const trigger = e.target.closest('[data-bs-toggle="dropdown"]');
        if (trigger) {
            e.preventDefault();
            e.stopPropagation();
            const parent = trigger.closest('.dropdown');
            if (!parent) return;
            const menu = parent.querySelector('.dropdown-menu');
            if (!menu) return;
            const isOpen = menu.classList.contains('show');
            closeAllDropdowns();
            if (!isOpen) {
                menu.classList.add('show');
                trigger.setAttribute('aria-expanded', 'true');
            }
            return;
        }
        closeAllDropdowns();
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeAllDropdowns();
    });

    const DropdownAPI = {
        getInstance: function(el) {
            if (!el) return null;
            return {
                hide: function() {
                    const parent = el.closest('.dropdown');
                    if (!parent) return;
                    const menu = parent.querySelector('.dropdown-menu');
                    if (menu) menu.classList.remove('show');
                    el.setAttribute('aria-expanded', 'false');
                }
            };
        }
    };

    /* ── Tooltip ── */
    let tooltipEl = null;

    function createTooltipEl() {
        if (tooltipEl) return tooltipEl;
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'tooltip-popup';
        tooltipEl.setAttribute('role', 'tooltip');
        const isCovert = document.body.classList.contains('covert-mode');
        const fg = isCovert ? '#cc2828' : '#e6edf3';
        const bg = isCovert ? '#0c0a0a' : '#30363d';
        const border = isCovert ? '1px solid rgba(180,30,30,0.45)' : 'none';
        tooltipEl.style.cssText = 'position:fixed;z-index:9999;max-width:300px;padding:6px 12px;' +
            'font-size:0.8125rem;line-height:1.4;color:' + fg + ';background:' + bg + ';' +
            'border:' + border + ';border-radius:6px;pointer-events:none;opacity:0;transition:opacity 0.15s;white-space:normal;';
        document.body.appendChild(tooltipEl);
        return tooltipEl;
    }

    function showTooltip(trigger) {
        const title = trigger.getAttribute('title') || trigger.getAttribute('data-bs-original-title');
        if (!title) return;
        if (trigger.getAttribute('title')) {
            trigger.setAttribute('data-bs-original-title', title);
            trigger.removeAttribute('title');
        }
        const tip = createTooltipEl();
        const isCovert = document.body.classList.contains('covert-mode');
        tip.style.color = isCovert ? '#cc2828' : '#e6edf3';
        tip.style.background = isCovert ? '#0c0a0a' : '#30363d';
        tip.style.border = isCovert ? '1px solid rgba(180,30,30,0.45)' : 'none';
        if (isCovert) tip.style.textShadow = '0 0 6px rgba(180,20,20,0.25)';
        else tip.style.textShadow = 'none';
        const useHtml = trigger.getAttribute('data-bs-html') === 'true';
        if (useHtml) {
            const parser = new DOMParser();
            const parsed = parser.parseFromString(title, 'text/html');
            const allowed = {STRONG: true, BR: true, B: true, EM: true, I: true};
            (function strip(node) {
                for (let i = node.childNodes.length - 1; i >= 0; i--) {
                    const child = node.childNodes[i];
                    if (child.nodeType === 1) {
                        if (!allowed[child.tagName]) {
                            while (child.firstChild) child.parentNode.insertBefore(child.firstChild, child);
                            child.parentNode.removeChild(child);
                        } else {
                            while (child.attributes.length) child.removeAttributeNode(child.attributes[0]);
                            strip(child);
                        }
                    }
                }
            })(parsed.body);
            while (tip.firstChild) tip.removeChild(tip.firstChild);
            while (parsed.body.firstChild) tip.appendChild(document.adoptNode(parsed.body.firstChild));
        } else {
            tip.textContent = title;
        }
        tip.style.opacity = '1';
        const rect = trigger.getBoundingClientRect();
        const tipWidth = tip.offsetWidth;
        let left = rect.left + rect.width / 2 - tipWidth / 2;
        if (left < 8) left = 8;
        if (left + tipWidth > window.innerWidth - 8) left = window.innerWidth - tipWidth - 8;
        let top = rect.top - tip.offsetHeight - 6;
        if (top < 8) top = rect.bottom + 6;
        tip.style.left = left + 'px';
        tip.style.top = top + 'px';
    }

    function hideTooltip(trigger) {
        if (tooltipEl) tooltipEl.style.opacity = '0';
        if (trigger) {
            const orig = trigger.getAttribute('data-bs-original-title');
            if (orig) trigger.setAttribute('title', orig);
        }
    }

    function initTooltips(root) {
        const rootEl = root || document;
        if (rootEl._foundationTooltipsInit) return;
        rootEl._foundationTooltipsInit = true;
        const triggers = rootEl.querySelectorAll('[data-bs-toggle="tooltip"]');
        for (let i = 0; i < triggers.length; i++) {
            (function(el) {
                el.addEventListener('mouseenter', function() { showTooltip(el); });
                el.addEventListener('mouseleave', function() { hideTooltip(el); });
                el.addEventListener('focus', function() { showTooltip(el); });
                el.addEventListener('blur', function() { hideTooltip(el); });
            })(triggers[i]);
        }
    }

    const TooltipAPI = function(el) {
        if (!el) return;
        el.addEventListener('mouseenter', function() { showTooltip(el); });
        el.addEventListener('mouseleave', function() { hideTooltip(el); });
        el.addEventListener('focus', function() { showTooltip(el); });
        el.addEventListener('blur', function() { hideTooltip(el); });
    };

    /* ── Alert dismiss ── */
    document.addEventListener('click', function(e) {
        const btn = e.target.closest('[data-bs-dismiss="alert"]');
        if (!btn) return;
        const alert = btn.closest('.alert');
        if (alert) {
            alert.style.opacity = '0';
            setTimeout(function() { alert.remove(); }, 150);
        }
    });

    /* ── Tab/Pill toggle ── */
    document.addEventListener('click', function(e) {
        const trigger = e.target.closest('[data-bs-toggle="tab"], [data-bs-toggle="pill"]');
        if (!trigger) return;
        e.preventDefault();
        const selector = trigger.getAttribute('data-bs-target') || trigger.getAttribute('href');
        if (!selector) return;
        const tabContent = document.querySelector(selector);
        if (!tabContent) return;
        const parent = trigger.closest('.nav');
        if (parent) {
            const siblings = parent.querySelectorAll('.nav-link');
            for (let i = 0; i < siblings.length; i++) {
                siblings[i].classList.remove('active');
                siblings[i].setAttribute('aria-selected', 'false');
            }
        }
        trigger.classList.add('active');
        trigger.setAttribute('aria-selected', 'true');
        const container = tabContent.parentNode;
        if (container) {
            const panes = container.querySelectorAll('.tab-pane');
            for (let j = 0; j < panes.length; j++) {
                panes[j].classList.remove('show', 'active');
            }
        }
        tabContent.classList.add('show', 'active');
    });

    /* ── Init on DOMContentLoaded ── */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() { initTooltips(); });
    } else {
        initTooltips();
    }

    /* ── Alert API ── */
    const AlertAPI = {
        getOrCreateInstance: function(el) {
            return {
                close: function() {
                    if (!el) return;
                    el.style.opacity = '0';
                    el.style.transition = 'opacity 0.15s';
                    setTimeout(function() { el.remove(); }, 150);
                }
            };
        }
    };

    /* ── Public API (replaces bootstrap.Dropdown, bootstrap.Tooltip, bootstrap.Alert) ── */
    window.bootstrap = {
        Dropdown: DropdownAPI,
        Tooltip: TooltipAPI,
        Alert: AlertAPI
    };
})();
