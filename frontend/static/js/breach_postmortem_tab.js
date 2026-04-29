/**
 * Postmortem Tab Loader
 * =====================
 *
 * Mirrors the existing pattern in static/js/breach_cluster_tab.js — adds a
 * "Postmortem" tab to the cluster drilldown view in breach.html. The tab
 * lazy-loads breach_postmortem.js when first opened to avoid bloating the
 * initial page render.
 *
 * INTEGRATION
 * -----------
 * In breach.html, find the existing tab strip (search for the line that
 * adds the "Cluster" tab — around the dispatch panel). Add this tab next
 * to the existing ones:
 *
 *     <button class="tab-button" data-tab="postmortem"
 *             id="postmortem-tab-button">Postmortem</button>
 *
 * And the matching panel:
 *
 *     <div class="tab-panel" id="postmortem-tab-panel"
 *          data-tab-content="postmortem"></div>
 *
 * Then include this loader and the renderer in the script section:
 *
 *     <script src="/static/js/breach_postmortem_tab.js"></script>
 *     <script src="/static/js/breach_postmortem.js"></script>
 *
 * In breach.js, find the existing dispatch panel "Generate Deep Report"
 * button (search for "Generate Deep Report" or "/api/v1/report/ingestion").
 * Re-route it to call window.JanusecPostmortem.openTab(assessmentId, clusterId)
 * instead of the report ingestion endpoint.
 *
 * GLOBAL HOOK
 * -----------
 * Exposes window.JanusecPostmortem with:
 *   .openTab(assessmentId, clusterId)
 *   .ensureLoaded()  — preloads the renderer module
 */

(function () {
  'use strict';

  const POSTMORTEM_RENDERER_KEY = '__janusec_postmortem_loaded';

  function ensureLoaded() {
    if (window[POSTMORTEM_RENDERER_KEY]) {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      // breach_postmortem.js attaches to window.JanusecPostmortem.render
      const existing = document.querySelector('script[data-janusec-postmortem]');
      if (existing) {
        // Wait for it to finish loading.
        existing.addEventListener('load', () => {
          window[POSTMORTEM_RENDERER_KEY] = true;
          resolve();
        });
        existing.addEventListener('error', reject);
        return;
      }
      // Already in DOM via static include — mark loaded.
      if (window.JanusecPostmortem && typeof window.JanusecPostmortem.render === 'function') {
        window[POSTMORTEM_RENDERER_KEY] = true;
        resolve();
        return;
      }
      reject(new Error('breach_postmortem.js not loaded'));
    });
  }

  function openTab(assessmentId, clusterId) {
    // If the postmortem tab panel is already mounted in the DOM (i.e. we are
    // already on ?tab=postmortem), render directly into it.
    const existingPanel = document.getElementById('postmortem-tab-panel');
    if (existingPanel) {
      existingPanel.innerHTML = '<div class="postmortem-loading">Loading postmortem…</div>';
      ensureLoaded()
        .then(() => window.JanusecPostmortem.render(existingPanel, assessmentId, clusterId))
        .catch(err => {
          existingPanel.innerHTML =
            '<div class="postmortem-error">Failed to load postmortem module: ' +
            escapeHtml(String(err && err.message || err)) + '</div>';
        });
      return;
    }

    // Otherwise navigate to the postmortem tab URL. breach.js renderPostmortemTab()
    // will mount the panel and call JanusecPostmortem.render() from there.
    const base = '?assessment=' + encodeURIComponent(assessmentId);
    window.location.href = '/static/breach.html' + base + '&tab=postmortem';
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  // Expose minimal API.
  window.JanusecPostmortem = window.JanusecPostmortem || {};
  window.JanusecPostmortem.openTab = openTab;
  window.JanusecPostmortem.ensureLoaded = ensureLoaded;

  // Wire the tab button click directly so it works without going through
  // the dispatch panel (analyst can click the tab itself if a postmortem
  // already exists).
  document.addEventListener('DOMContentLoaded', () => {
    const tabButton = document.getElementById('postmortem-tab-button');
    if (!tabButton) return;
    tabButton.addEventListener('click', () => {
      const ctx = window.__janusec_current_cluster_context;
      if (!ctx || !ctx.assessment_id || !ctx.cluster_id) {
        const tabPanel = document.getElementById('postmortem-tab-panel');
        if (tabPanel) {
          tabPanel.innerHTML = '<div class="postmortem-empty">Select a cluster to view its postmortem.</div>';
        }
        return;
      }
      openTab(ctx.assessment_id, ctx.cluster_id);
    });
  });
})();
