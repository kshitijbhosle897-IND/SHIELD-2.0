/* ==========================================================================
   history.js — Analysis history (localStorage)
   --------------------------------------------------------------------------
   Stores ONLY: timestamp, risk level, score and category for each analysis.
   The full message text is never persisted, by design.
   ========================================================================== */

const SpamShieldHistory = (() => {
  const STORAGE_KEY = 'spamshield_history';
  const MAX_ENTRIES = 10;

  function readAll() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (err) {
      console.warn('SHIELD 2.0: could not read history from localStorage.', err);
      return [];
    }
  }

  function add(entry) {
    const list = readAll();
    list.unshift({
      timestamp: entry.timestamp,
      levelKey: entry.level.key,
      levelLabel: entry.level.label,
      score: entry.score,
      category: entry.category
    });
    const trimmed = list.slice(0, MAX_ENTRIES);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    } catch (err) {
      console.warn('SHIELD 2.0: could not save history to localStorage.', err);
    }
    return trimmed;
  }

  function clear() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (err) {
      console.warn('SHIELD 2.0: could not clear history from localStorage.', err);
    }
  }

  function formatTimestamp(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
  }

  return { readAll, add, clear, formatTimestamp };
})();
