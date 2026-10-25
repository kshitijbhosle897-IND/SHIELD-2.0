/* ==========================================================================
   analyzer.js — SHIELD 2.0 detection engine
   --------------------------------------------------------------------------
   This file implements a deterministic, rule-based message analyzer.
   No machine learning is used and no network requests are made — every
   score is fully explainable from the keyword/pattern rules defined below.

   Public entry point:
       SpamShieldAnalyzer.analyzeMessage({ type, sender, message, url })

   The function is written as a single, self-contained module so that a
   real AI/backend API could later be swapped in behind the same
   analyzeMessage(message) signature without changing any calling code.
   ========================================================================== */

const SpamShieldAnalyzer = (() => {

  /* ---------------------------------------------------------------------
     1. INDICATOR DEFINITIONS
     Each indicator has: a display label, an icon, a severity (used for
     styling + highlighting), a point weight, and the keyword/phrase list
     used to detect it. All matching is case-insensitive, substring based.
     --------------------------------------------------------------------- */
  const INDICATORS = {
    urgency: {
      label: 'Urgency Detected',
      icon: 'fa-solid fa-bolt',
      severity: 'medium',
      weight: 20,
      description: 'The message pressures you to act immediately, often against a countdown or deadline.',
      keywords: [
        'urgent', 'immediately', 'act now', 'act fast', 'right away',
        'final notice', 'last chance', 'limited time', 'expires today',
        'expire soon', 'within 24 hours', 'within 12 hours', 'time-sensitive',
        'failure to act', 'account will be suspended', 'account suspended',
        'account blocked', 'will be blocked', 'permanently blocked',
        'immediate action required', 'respond immediately'
      ]
    },
    financial: {
      label: 'Financial Incentive',
      icon: 'fa-solid fa-money-bill-wave',
      severity: 'medium',
      weight: 15,
      description: 'The message mentions money, a payment, a refund, or an upfront fee.',
      keywords: [
        'payment', 'refund', 'invoice', 'processing fee', 'registration fee',
        'redelivery fee', 'small fee', 'shipping fee', 'customs fee',
        'guaranteed income', 'guaranteed pay', 'guaranteed weekly pay',
        'cash prize', 'earn money', 'wire transfer', 'bank transfer',
        'gift card', 'one-time fee', 'training materials fee'
      ]
    },
    reward: {
      label: 'Unexpected Reward',
      icon: 'fa-solid fa-gift',
      severity: 'medium',
      weight: 15,
      description: 'The message claims you won or were unexpectedly selected for something of value.',
      keywords: [
        'congratulations', 'you have won', "you've won", 'you have been selected',
        "you've been selected", 'winner', 'lucky winner', 'lottery', 'prize',
        'selected to receive', 'free gift', 'jackpot', 'sweepstakes'
      ]
    },
    sensitiveInfo: {
      label: 'Sensitive Information Request',
      icon: 'fa-solid fa-key',
      severity: 'high',
      weight: 25,
      description: 'The message asks for credentials, one-time codes, or other private information.',
      keywords: [
        'otp', 'one-time password', 'one time password', 'password', 'pin number',
        'cvv', 'social security', 'ssn', 'card number', 'account number',
        'login credentials', 'verify your account', 'verify your identity',
        'update your account', 'confirm your details', 'security code',
        'confirm your password'
      ]
    },
    suspiciousLink: {
      label: 'Suspicious Link',
      icon: 'fa-solid fa-link',
      severity: 'high',
      weight: 20,
      description: 'The message encourages clicking an external or unfamiliar link.',
      keywords: [
        'click here', 'click below', 'click this link', 'tap here',
        'follow this link', 'download the attachment', 'open the attachment',
        'click the link'
      ]
    },
    impersonation: {
      label: 'Impersonation / Fake Authority',
      icon: 'fa-solid fa-user-tie',
      severity: 'high',
      weight: 15,
      description: 'The message poses as a bank, government body, or official department to appear trustworthy.',
      keywords: [
        'this is an automated message from', 'official communication',
        'department of', 'law enforcement', 'legal action will be taken',
        'irs', 'tax department', 'security department', 'customer support team',
        'official notice'
      ]
    },
    formatting: {
      label: 'Excessive Formatting',
      icon: 'fa-solid fa-triangle-exclamation',
      severity: 'low',
      weight: 5,
      description: 'Heavy use of capital letters or exclamation marks is a common pressure tactic.',
      keywords: [] // detected structurally, not by keyword — see detectExcessiveFormatting()
    },
    unknownSender: {
      label: 'Unknown Sender',
      icon: 'fa-solid fa-user-secret',
      severity: 'low',
      weight: 5,
      description: 'No sender was provided, making it hard to verify who actually sent this message.',
      keywords: []
    }
  };

  // Secondary keyword sets used only for category classification (not scored directly)
  const JOB_KEYWORDS = [
    'hiring', 'job offer', 'work from home', 'work-from-home', 'interview',
    'recruiter', 'position available', 'no experience required', 'data entry',
    'training materials', 'secure your position', 'job opportunity'
  ];
  const DELIVERY_KEYWORDS = [
    'package', 'delivery', 'courier', 'shipment', 'parcel', 'customs',
    'redelivery', 'tracking number', 'returned to sender', 'reschedule delivery'
  ];
  const SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly'];

  /* ---------------------------------------------------------------------
     2. LOW-LEVEL HELPERS
     --------------------------------------------------------------------- */

  // Escape HTML special characters so user input can never inject markup.
  function escapeHTML(str) {
    return String(str)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  // Escape a string for safe use inside a RegExp.
  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Return the subset of `keywords` that appear (case-insensitive) in `text`.
  function findMatches(text, keywords) {
    const lower = text.toLowerCase();
    return keywords.filter((kw) => lower.includes(kw.toLowerCase()));
  }

  // Detect ALL-CAPS shouting and repeated exclamation marks.
  function detectExcessiveFormatting(text) {
    const exclamationRun = /!{2,}/.test(text);
    const capsWords = (text.match(/\b[A-Z]{4,}\b/g) || []);
    return { flagged: exclamationRun || capsWords.length >= 2, exclamationRun, capsWordCount: capsWords.length };
  }

  // Inspect an (optional) URL for common red flags.
  function analyzeUrl(url) {
    if (!url || !url.trim()) return { provided: false, suspicious: false, reasons: [] };
    const reasons = [];
    const lower = url.toLowerCase().trim();
    const isIp = /^https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(lower);
    const isShortener = SHORTENER_DOMAINS.some((d) => lower.includes(d));
    const oddTld = /\.(xyz|top|club|info|click|loan)\b/.test(lower);
    const noHttps = /^http:\/\//.test(lower);
    if (isIp) reasons.push('uses a raw IP address instead of a domain name');
    if (isShortener) reasons.push('uses a link-shortening service that hides the real destination');
    if (oddTld) reasons.push('uses a domain ending commonly associated with disposable scam sites');
    if (noHttps) reasons.push('is not using a secure (https) connection');
    return { provided: true, suspicious: reasons.length > 0, reasons };
  }

  /* ---------------------------------------------------------------------
     3. CATEGORY CLASSIFICATION
     Runs the more specific classifiers (job / delivery) first, then falls
     back to general combinations, so results stay explainable.
     --------------------------------------------------------------------- */
  function classifyCategory(flags, text) {
    const lower = text.toLowerCase();
    const jobHit = JOB_KEYWORDS.some((k) => lower.includes(k));
    const deliveryHit = DELIVERY_KEYWORDS.some((k) => lower.includes(k));

    if (jobHit && (flags.financial || flags.reward)) return 'Likely Job Scam';
    if (deliveryHit && (flags.financial || flags.suspiciousLink || flags.urgency)) return 'Likely Delivery / Courier Scam';
    if (flags.sensitiveInfo) return 'Potential Phishing (Credential Theft)';
    if (flags.reward && flags.financial) return 'Likely Prize / Lottery Scam';
    if (flags.impersonation && flags.urgency) return 'Likely Impersonation Scam';
    if (flags.suspiciousLink && flags.urgency) return 'Potential Phishing / Scam';
    return null; // resolved by score thresholds in analyzeMessage()
  }

  function riskLevelForScore(score) {
    if (score >= 80) return { key: 'veryhigh', label: 'VERY HIGH RISK', emoji: '🔴' };
    if (score >= 60) return { key: 'high', label: 'HIGH RISK', emoji: '🟠' };
    if (score >= 30) return { key: 'suspicious', label: 'SUSPICIOUS', emoji: '🟡' };
    return { key: 'low', label: 'LOW RISK', emoji: '🟢' };
  }

  /* ---------------------------------------------------------------------
     4. RECOMMENDATIONS
     Priority (context-specific) recommendations, ordered by relevance.
     The general 6-point checklist is rendered separately in the HTML.
     --------------------------------------------------------------------- */
  function buildPriorityRecommendations(flags) {
    const rec = [];
    if (flags.sensitiveInfo) rec.push('Never reply with passwords, OTPs, PINs or banking details — no legitimate organization asks for these by message.');
    if (flags.suspiciousLink) rec.push('Do not click the link in this message. Go directly to the official website or app instead.');
    if (flags.reward || flags.financial) rec.push("Do not pay a \"fee\" to claim a prize, refund or job — legitimate rewards never require upfront payment.");
    if (flags.urgency) rec.push('Slow down. Scammers manufacture urgency so you act before thinking it through.');
    if (flags.impersonation || flags.unknownSender) rec.push('Verify the sender through an official, independently-sourced contact channel before responding.');
    if (rec.length === 0) rec.push('No major red flags were found — but stay alert for requests that seem unusual for this sender.');
    return rec;
  }

  /* ---------------------------------------------------------------------
     5. HIGHLIGHTING
     Builds safe HTML: escape first, then wrap ONLY our own <mark> tags
     around matched terms — the user's text is never treated as markup.
     --------------------------------------------------------------------- */
  function buildHighlightedHTML(rawText, matchedByIndicator) {
    // Collect all matched terms with their severity, longest-first so that
    // longer phrases are wrapped before their shorter substrings.
    const terms = [];
    Object.entries(matchedByIndicator).forEach(([key, terms_]) => {
      const severity = INDICATORS[key]?.severity || 'low';
      terms_.forEach((t) => terms.push({ term: t, severity }));
    });
    terms.sort((a, b) => b.term.length - a.term.length);

    let escaped = escapeHTML(rawText);
    terms.forEach(({ term, severity }) => {
      if (severity === 'low') return; // only highlight medium/high severity terms
      const cls = severity === 'high' ? 'hl-high' : 'hl-medium';
      const pattern = new RegExp('(' + escapeRegExp(escapeHTML(term)) + ')', 'ig');
      // Avoid re-wrapping text that's already inside a <mark> tag.
      escaped = escaped.replace(pattern, (match, _p1, offset, whole) => {
        const before = whole.slice(0, offset);
        const openCount = (before.match(/<mark/g) || []).length;
        const closeCount = (before.match(/<\/mark>/g) || []).length;
        if (openCount > closeCount) return match; // already inside a mark
        return `<mark class="${cls}">${match}</mark>`;
      });
    });
    return escaped;
  }

  /* ---------------------------------------------------------------------
     6. MAIN ENTRY POINT
     --------------------------------------------------------------------- */
  function analyzeMessage({ type = 'Email', sender = '', message = '', url = '' } = {}) {
    const text = message || '';
    const matchedByIndicator = {};
    const flags = {};
    let score = 0;
    const firedIndicators = [];

    // Keyword-based indicators
    ['urgency', 'financial', 'reward', 'sensitiveInfo', 'suspiciousLink', 'impersonation'].forEach((key) => {
      const matches = findMatches(text, INDICATORS[key].keywords);
      matchedByIndicator[key] = matches;
      flags[key] = matches.length > 0;
      if (flags[key]) {
        score += INDICATORS[key].weight;
        firedIndicators.push(key);
      }
    });

    // A provided URL also counts toward the "suspicious link" indicator,
    // even if no "click here"-style phrase was used.
    const urlAnalysis = analyzeUrl(url);
    if (urlAnalysis.provided && !flags.suspiciousLink) {
      flags.suspiciousLink = true;
      score += INDICATORS.suspiciousLink.weight;
      firedIndicators.push('suspiciousLink');
    }

    // Structural indicators
    const formatting = detectExcessiveFormatting(text);
    flags.formatting = formatting.flagged;
    if (flags.formatting) { score += INDICATORS.formatting.weight; firedIndicators.push('formatting'); }

    flags.unknownSender = !sender || !sender.trim();
    if (flags.unknownSender) { score += INDICATORS.unknownSender.weight; firedIndicators.push('unknownSender'); }

    score = Math.min(100, score);

    const level = riskLevelForScore(score);
    let category = classifyCategory(flags, text);
    if (!category) {
      category = score >= 30 ? 'Suspicious Message / Possible Scam' : 'No Significant Threats Detected';
    }

    const indicators = firedIndicators.map((key) => ({
      key,
      label: INDICATORS[key].label,
      icon: INDICATORS[key].icon,
      severity: INDICATORS[key].severity,
      description: INDICATORS[key].description
    }));

    return {
      score,
      level,               // { key, label, emoji }
      category,
      type,
      indicators,          // array of { key, label, icon, severity, description }
      priorityRecommendations: buildPriorityRecommendations(flags),
      highlightedHTML: buildHighlightedHTML(text, matchedByIndicator),
      urlAnalysis,
      timestamp: new Date().toISOString()
    };
  }

  return { analyzeMessage };
})();
