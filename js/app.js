/* ==========================================================================
   app.js — SHIELD 2.0 UI wiring
   --------------------------------------------------------------------------
   Connects the analyzer, history and quiz modules to the page: navigation,
   sample messages, the detector form, results rendering, and the static
   threat-library / safety-tips content.
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {

  /* -------------------- Navigation -------------------- */
  const navToggle = document.getElementById('navToggle');
  const navLinks = document.getElementById('navLinks');

  navToggle.addEventListener('click', () => {
    const isOpen = navLinks.classList.toggle('open');
    navToggle.setAttribute('aria-expanded', String(isOpen));
  });
  navLinks.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      navLinks.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    });
  });

  /* -------------------- Sample messages -------------------- */
  const SAMPLES = {
    prize: {
      type: 'Email',
      sender: 'rewards@lucky-prizes-intl.com',
      message: "CONGRATULATIONS!!! You have been selected as our LUCKY WINNER of a $1,000,000 cash prize in this month's international lottery draw! To claim your prize, you must act immediately and pay a small registration fee of $50 within 24 hours. Click here to claim now before your prize expires!",
      url: 'http://claim-your-prize-now.xyz/winner'
    },
    bank: {
      type: 'Email',
      sender: 'security@yourbank-alerts.com',
      message: 'OFFICIAL NOTICE: This is an automated message from the Security Department. Your account access will be permanently blocked within 24 hours. IMMEDIATE ACTION REQUIRED — verify your account by clicking the link below and confirm your password and OTP to restore access.',
      url: 'http://secure-yourbank-verify.com/login'
    },
    job: {
      type: 'Email',
      sender: 'hr@quickhire-remote.com',
      message: 'Congratulations! You have been selected for a work-from-home data entry position with guaranteed weekly pay of $800. No experience required. To secure your position, please pay a one-time registration fee of $45 for training materials. Act now, limited seats available!',
      url: 'http://quickhire-remote-apply.xyz/register'
    },
    delivery: {
      type: 'SMS',
      sender: 'DeliveryUpdates',
      message: 'Your package could not be delivered due to an incomplete address. A small redelivery fee of $2.99 is required to reschedule delivery. Please use the link below to complete this.',
      url: 'http://track-parcel-redeliver.xyz/pay'
    },
    normal: {
      type: 'SMS',
      sender: 'Mom',
      message: 'Hey! Just checking in, are we still on for dinner tomorrow at 7? Let me know if you need directions to the restaurant. See you soon!',
      url: ''
    }
  };

  const msgType = document.getElementById('msgType');
  const msgSender = document.getElementById('msgSender');
  const msgText = document.getElementById('msgText');
  const msgUrl = document.getElementById('msgUrl');
  const msgTextError = document.getElementById('msgTextError');

  document.querySelectorAll('[data-sample]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const s = SAMPLES[btn.dataset.sample];
      if (!s) return;
      msgType.value = s.type;
      msgSender.value = s.sender;
      msgText.value = s.message;
      msgUrl.value = s.url;
      msgTextError.hidden = true;
      msgText.focus();
    });
  });

  /* -------------------- Detector form -------------------- */
  const form = document.getElementById('detectorForm');
  const scanLoading = document.getElementById('scanLoading');
  const resultsEl = document.getElementById('results');

  form.addEventListener('submit', (e) => {
    e.preventDefault();

    if (!msgText.value.trim()) {
      msgTextError.hidden = false;
      msgText.focus();
      return;
    }
    msgTextError.hidden = true;

    form.hidden = true;
    scanLoading.hidden = false;
    resultsEl.hidden = true;

    // Brief simulated scan delay so the analysis feels like a real check.
    setTimeout(async () => {
    const result = SpamShieldAnalyzer.analyzeMessage({
    type: msgType.value,
    sender: msgSender.value,
    message: msgText.value,
    url: msgUrl.value
  });

    try {
      const mlResponse = await fetch('http://127.0.0.1:5000/predict', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: msgText.value
        })
      });

      if (mlResponse.ok) {
        const mlResult = await mlResponse.json();
        result.mlPrediction = mlResult.prediction;
        result.mlProbability = mlResult.spam_probability;
      }
    } catch (err) {
      console.warn('Flask ML API unreachable; using local rule-based analysis.', err);
    }

      renderResults(result);
      const updatedHistory = SpamShieldHistory.add(result);
      renderHistory(updatedHistory);

      scanLoading.hidden = true;
      form.hidden = false;
      resultsEl.hidden = false;
      resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 900);
  });

  const RISK_VAR = { low: '--green', suspicious: '--yellow', high: '--orange', veryhigh: '--red' };
  const CIRCUMFERENCE = 2 * Math.PI * 70; // matches r=70 in the SVG gauge

  function renderResults(result) {
    // Gauge
    const gaugeFill = document.getElementById('gaugeFill');
    const offset = CIRCUMFERENCE * (1 - result.score / 100);
    gaugeFill.style.stroke = `var(${RISK_VAR[result.level.key]})`;
    // Force reflow so the transition always animates from the previous state.
    gaugeFill.style.strokeDashoffset = CIRCUMFERENCE;
    requestAnimationFrame(() => { gaugeFill.style.strokeDashoffset = offset; });
    document.getElementById('gaugeScore').textContent = result.score;

    // Badge + category + meta
    const badge = document.getElementById('riskBadge');
    badge.className = 'risk-badge bg-risk-' + result.level.key;
    document.getElementById('riskBadgeText').textContent = `${result.level.emoji} ${result.level.label}`;
    document.getElementById('resultCategory').textContent = result.category;
    document.getElementById('resultTimestamp').textContent = SpamShieldHistory.formatTimestamp(result.timestamp);
    document.getElementById('resultType').textContent = result.type;

    // Machine Learning Detection Result
    let mlBox = document.getElementById('mlDetectionResult');
    if (result.mlPrediction) {
      if (!mlBox) {
        mlBox = document.createElement('div');
        mlBox.id = 'mlDetectionResult';
        mlBox.style.marginTop = '20px';
        mlBox.style.padding = '16px';
        mlBox.style.borderRadius = '12px';
        mlBox.style.background = 'var(--surface, #f5f5f5)';
        mlBox.style.border = '1px solid rgba(128,128,128,0.25)';

        document.getElementById('results').prepend(mlBox);
      }

      const mlLabel =
        result.mlPrediction === 'spam' ? 'SPAM' : 'NOT SPAM';

      mlBox.innerHTML = `
        <h3>🤖 Machine Learning Detection</h3>
        <p><strong>Prediction:</strong> ${mlLabel}</p>
        <p><strong>Spam Probability:</strong> ${result.mlProbability}%</p>
      `;
    } else if (mlBox) {
      mlBox.remove();
    }
    
    // Indicators
    const grid = document.getElementById('indicatorGrid');
    if (result.indicators.length === 0) {
      grid.innerHTML = '<p class="history-empty">No warning-sign patterns were detected in this message.</p>';
    } else {
      grid.innerHTML = result.indicators.map((ind) => `
        <div class="indicator-card sev-${ind.severity}">
          <i class="${ind.icon}"></i>
          <div>
            <h5>${ind.label}</h5>
            <p>${ind.description}</p>
          </div>
        </div>
      `).join('');
    }

    // Highlighted message (already escaped/sanitized by the analyzer)
    document.getElementById('highlightedMessage').innerHTML = result.highlightedHTML || '<em>No message text provided.</em>';

    // Priority recommendations
    document.getElementById('priorityRecommendations').innerHTML =
      result.priorityRecommendations.map((r) => `<li>${escapeForDisplay(r)}</li>`).join('');
  }

  // Belt-and-braces escaping for any text we insert via innerHTML ourselves.
  function escapeForDisplay(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  /* -------------------- History -------------------- */
  const historyList = document.getElementById('historyList');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');

  function renderHistory(entries) {
    if (!entries || entries.length === 0) {
      historyList.innerHTML = '<p class="history-empty">No analyses yet — results you check will appear here.</p>';
      return;
    }
    historyList.innerHTML = entries.map((e) => `
      <div class="history-row">
        <span class="hr-time">${SpamShieldHistory.formatTimestamp(e.timestamp)}</span>
        <span class="hr-cat">${escapeForDisplay(e.category)}</span>
        <span class="hr-score">${e.score}/100</span>
        <span class="history-badge bg-risk-${e.levelKey}">${escapeForDisplay(e.levelLabel)}</span>
      </div>
    `).join('');
  }

  clearHistoryBtn.addEventListener('click', () => {
    SpamShieldHistory.clear();
    renderHistory([]);
  });

  renderHistory(SpamShieldHistory.readAll());

  /* -------------------- Threat library -------------------- */
  const THREATS = [
    { title: 'Phishing', icon: 'fa-solid fa-envelope-open-text',
      what: "Fraudulent emails designed to look like they're from a trusted organization, aiming to steal credentials or install malware.",
      signs: ['Generic greeting instead of your name', 'Mismatched or lookalike sender domain', 'Requests to "verify" your account or password'],
      protect: 'Go directly to the official website instead of clicking links in the email.' },
    { title: 'Smishing', icon: 'fa-solid fa-comment-sms',
      what: 'Phishing carried out over SMS/text message, often impersonating banks, delivery services or government agencies.',
      signs: ['Unexpected text from an unknown number', 'Shortened or unfamiliar links', 'Urgent account or delivery threats'],
      protect: 'Never tap links in unsolicited texts — verify through the official app instead.' },
    { title: 'Email Spam', icon: 'fa-solid fa-inbox',
      what: 'Unsolicited bulk email, ranging from harmless ads to disguised scams and malware.',
      signs: ["Sent without any prior signup", 'Excessive promotional or urgent language', 'Unfamiliar or spoofed sender address'],
      protect: "Use your provider's spam filter and avoid clicking \"unsubscribe\" from unknown senders." },
    { title: 'Prize Scams', icon: 'fa-solid fa-gift',
      what: "Messages claiming you've won a lottery, sweepstakes or prize you never entered.",
      signs: ["You don't recall entering the contest", 'A fee is required to release the prize', 'Pressure to claim within a short deadline'],
      protect: 'Remember: legitimate prizes never require you to pay first.' },
    { title: 'Job Scams', icon: 'fa-solid fa-briefcase',
      what: "Fake job offers that ask for money or personal information before you're ever actually hired.",
      signs: ['Payment requested for training or equipment', 'Vague job description with unusually high pay', 'Entire interview conducted only over chat'],
      protect: 'Research the company independently, and never pay to get hired.' },
    { title: 'Impersonation', icon: 'fa-solid fa-user-secret',
      what: 'Messages that pose as a bank, government agency or company representative to gain your trust.',
      signs: ['Generic or slightly-off sender address', 'Requests that bypass normal channels', 'Threats of legal or account consequences'],
      protect: 'Contact the organization directly using a number or site you found yourself.' },
    { title: 'Delivery Scams', icon: 'fa-solid fa-truck-fast',
      what: 'Fake shipping notifications asking you to pay a fee or click a link to "reschedule" delivery.',
      signs: ["You weren't expecting a package", 'A small "fee" is required to release the parcel', 'Link to an unfamiliar tracking site'],
      protect: "Track packages only through the courier's official app or website." },
    { title: 'OTP Scams', icon: 'fa-solid fa-key',
      what: 'Attempts to trick you into sharing a one-time passcode sent to your phone or email.',
      signs: ['Asked to "confirm" or read back a code you received', 'Claimed to be needed for a delivery, prize or account fix', 'Pressure to respond within minutes'],
      protect: 'Never share an OTP with anyone — it should stay between you and the service that sent it.' }
  ];

  document.getElementById('threatGrid').innerHTML = THREATS.map((t) => `
    <div class="threat-card">
      <h3><i class="${t.icon}"></i> ${t.title}</h3>
      <p>${t.what}</p>
      <p class="tc-label">Warning signs</p>
      <ul>${t.signs.map((s) => `<li>${s}</li>`).join('')}</ul>
      <p class="tc-label">Protection tip</p>
      <p class="tc-protect">${t.protect}</p>
    </div>
  `).join('');

  /* -------------------- Safety tips -------------------- */
  const TIPS = [
    { title: 'Think Before You Click', icon: 'fa-solid fa-hand-pointer',
      text: 'Pause before tapping any link, especially in an unexpected message. Scammers rely on quick, automatic reactions.' },
    { title: 'Protect Your Passwords & OTPs', icon: 'fa-solid fa-lock',
      text: 'Never share passwords, PINs or one-time codes with anyone — even someone claiming to be support staff.' },
    { title: 'Verify Financial Requests', icon: 'fa-solid fa-money-check-dollar',
      text: 'Confirm any request for money or payment details directly with the organization, using contact info you already trust.' },
    { title: 'Check the Sender', icon: 'fa-solid fa-magnifying-glass',
      text: 'Look closely at email addresses and phone numbers — small misspellings often reveal a fake sender.' },
    { title: "Don't Let Urgency Pressure You", icon: 'fa-solid fa-hourglass-half',
      text: 'Legitimate organizations rarely demand instant action. Take a moment before responding to an "urgent" message.' },
    { title: 'Avoid Unexpected Fees', icon: 'fa-solid fa-circle-exclamation',
      text: 'Be suspicious of any prize, refund, job or delivery that suddenly requires you to pay first.' }
  ];

  document.getElementById('tipsGrid').innerHTML = TIPS.map((t) => `
    <div class="tip-card">
      <h3><i class="${t.icon}"></i> ${t.title}</h3>
      <p>${t.text}</p>
    </div>
  `).join('');

  /* -------------------- Quiz -------------------- */
  SpamShieldQuiz.init();
});
