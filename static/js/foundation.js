(function() {
    'use strict';

    function getCspNonce() {
        var s = document.querySelector('script[nonce]');
        return s ? s.nonce || s.getAttribute('nonce') : '';
    }

    /* ── Collapse ── */
    function toggleCollapse(target) {
        if (!target) return;
        var isShown = target.classList.contains('show');
        if (isShown) {
            target.classList.add('collapsing');
            target.classList.remove('collapse', 'show');
            setTimeout(function() {
                target.classList.remove('collapsing');
                target.classList.add('collapse');
            }, 350);
        } else {
            target.classList.remove('collapse');
            target.classList.add('collapsing', 'collapsing-open');
            setTimeout(function() {
                target.classList.remove('collapsing', 'collapsing-open');
                target.classList.add('collapse', 'show');
            }, 350);
        }
        var triggers = document.querySelectorAll('[data-bs-target="#' + target.id + '"]');
        for (var i = 0; i < triggers.length; i++) {
            triggers[i].ariaExpanded = String(!isShown);
            if (!isShown) {
                triggers[i].classList.remove('collapsed');
            } else {
                triggers[i].classList.add('collapsed');
            }
        }
    }

    document.addEventListener('click', function(e) {
        var trigger = e.target.closest('[data-bs-toggle="collapse"]');
        if (!trigger) return;
        e.preventDefault();
        var selector = trigger.getAttribute('data-bs-target');
        if (!selector) return;
        var target = document.querySelector(selector);
        toggleCollapse(target);
    });

    /* ── Dropdown ── */
    function closeAllDropdowns(except) {
        var openMenus = document.querySelectorAll('.dropdown-menu.show');
        for (var i = 0; i < openMenus.length; i++) {
            if (except && openMenus[i] === except) continue;
            openMenus[i].classList.remove('show');
            var parent = openMenus[i].closest('.dropdown');
            if (parent) {
                var toggle = parent.querySelector('[data-bs-toggle="dropdown"]');
                if (toggle) toggle.ariaExpanded = 'false';
            }
        }
    }

    document.addEventListener('click', function(e) {
        var trigger = e.target.closest('[data-bs-toggle="dropdown"]');
        if (trigger) {
            e.preventDefault();
            e.stopPropagation();
            var parent = trigger.closest('.dropdown');
            if (!parent) return;
            var menu = parent.querySelector('.dropdown-menu');
            if (!menu) return;
            var isOpen = menu.classList.contains('show');
            closeAllDropdowns();
            if (!isOpen) {
                menu.classList.add('show');
                trigger.ariaExpanded = 'true';
            }
            return;
        }
        closeAllDropdowns();
    });

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') closeAllDropdowns();
    });

    var DropdownAPI = {
        getInstance: function(el) {
            if (!el) return null;
            return {
                hide: function() {
                    var parent = el.closest('.dropdown');
                    if (!parent) return;
                    var menu = parent.querySelector('.dropdown-menu');
                    if (menu) menu.classList.remove('show');
                    el.ariaExpanded = 'false';
                }
            };
        }
    };

    /* ── Tooltip ── */
    var tooltipEl = null;
    var tooltipStyleEl = null;

    function ensureTooltipStyleEl() {
        if (tooltipStyleEl) return tooltipStyleEl;
        tooltipStyleEl = document.createElement('style');
        var nonce = getCspNonce();
        if (nonce) tooltipStyleEl.setAttribute('nonce', nonce);
        document.head.appendChild(tooltipStyleEl);
        return tooltipStyleEl;
    }

    function createTooltipEl() {
        if (tooltipEl) return tooltipEl;
        tooltipEl = document.createElement('div');
        tooltipEl.className = 'tooltip-popup';
        tooltipEl.role = 'tooltip';
        var isCovert = document.body.classList.contains('covert-mode');
        if (isCovert) {
            tooltipEl.classList.add('tooltip-covert');
        }
        document.body.appendChild(tooltipEl);
        return tooltipEl;
    }

    function showTooltip(trigger) {
        var title = trigger.getAttribute('title') || trigger.getAttribute('data-bs-original-title');
        if (!title) return;
        if (trigger.getAttribute('title')) {
            trigger.dataset.bsOriginalTitle = title;
            trigger.removeAttribute('title');
        }
        var tip = createTooltipEl();
        var isCovert = document.body.classList.contains('covert-mode');
        if (isCovert) {
            tip.classList.add('tooltip-covert');
        } else {
            tip.classList.remove('tooltip-covert');
        }
        var useHtml = trigger.getAttribute('data-bs-html') === 'true';
        if (useHtml) {
            var parser = new DOMParser();
            var parsed = parser.parseFromString(title, 'text/html');
            var allowed = {STRONG: true, BR: true, B: true, EM: true, I: true};
            (function strip(node) {
                for (var i = node.childNodes.length - 1; i >= 0; i--) {
                    var child = node.childNodes[i];
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
        tip.classList.add('tooltip-visible');
        var rect = trigger.getBoundingClientRect();
        var tipWidth = tip.offsetWidth;
        var left = rect.left + rect.width / 2 - tipWidth / 2;
        if (left < 8) left = 8;
        if (left + tipWidth > window.innerWidth - 8) left = window.innerWidth - tipWidth - 8;
        var top = rect.top - tip.offsetHeight - 6;
        if (top < 8) top = rect.bottom + 6;
        var sel = ensureTooltipStyleEl();
        sel.textContent = '.tooltip-popup.tooltip-visible{left:' + left + 'px;top:' + top + 'px}';
    }

    function hideTooltip(trigger) {
        if (tooltipEl) tooltipEl.classList.remove('tooltip-visible');
        if (trigger) {
            var orig = trigger.getAttribute('data-bs-original-title');
            if (orig) trigger.title = orig;
        }
    }

    function initTooltips(root) {
        var rootEl = root || document;
        if (rootEl._foundationTooltipsInit) return;
        rootEl._foundationTooltipsInit = true;
        var triggers = rootEl.querySelectorAll('[data-bs-toggle="tooltip"]');
        for (var i = 0; i < triggers.length; i++) {
            (function(el) {
                el.addEventListener('mouseenter', function() { showTooltip(el); });
                el.addEventListener('mouseleave', function() { hideTooltip(el); });
                el.addEventListener('focus', function() { showTooltip(el); });
                el.addEventListener('blur', function() { hideTooltip(el); });
            })(triggers[i]);
        }
    }

    var TooltipAPI = function(el) {
        if (!el) return;
        el.addEventListener('mouseenter', function() { showTooltip(el); });
        el.addEventListener('mouseleave', function() { hideTooltip(el); });
        el.addEventListener('focus', function() { showTooltip(el); });
        el.addEventListener('blur', function() { hideTooltip(el); });
    };

    /* ── Alert dismiss ── */
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-bs-dismiss="alert"]');
        if (!btn) return;
        var alert = btn.closest('.alert');
        if (alert) {
            alert.classList.add('alert-dismissing');
            setTimeout(function() { alert.remove(); }, 150);
        }
    });

    /* ── Tab/Pill toggle ── */
    document.addEventListener('click', function(e) {
        var trigger = e.target.closest('[data-bs-toggle="tab"], [data-bs-toggle="pill"]');
        if (!trigger) return;
        e.preventDefault();
        var selector = trigger.getAttribute('data-bs-target') || trigger.getAttribute('href');
        if (!selector) return;
        var tabContent = document.querySelector(selector);
        if (!tabContent) return;
        var parent = trigger.closest('.nav');
        if (parent) {
            var siblings = parent.querySelectorAll('.nav-link');
            for (var i = 0; i < siblings.length; i++) {
                siblings[i].classList.remove('active');
                siblings[i].ariaSelected = 'false';
            }
        }
        trigger.classList.add('active');
        trigger.ariaSelected = 'true';
        var container = tabContent.parentNode;
        if (container) {
            var panes = container.querySelectorAll('.tab-pane');
            for (var j = 0; j < panes.length; j++) {
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
    var AlertAPI = {
        getOrCreateInstance: function(el) {
            return {
                close: function() {
                    if (!el) return;
                    el.classList.add('alert-dismissing');
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
