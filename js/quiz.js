/* ==========================================================================
   quiz.js — Cyber Safety Quiz
   --------------------------------------------------------------------------
   Renders one question at a time, gives immediate feedback with an
   explanation, tracks score, and supports retaking the quiz.
   ========================================================================== */

const SpamShieldQuiz = (() => {
  const QUESTIONS = [
    {
      question: "You receive a message saying your bank account will be blocked unless you click a link. What should you do?",
      options: [
        "Click the link right away to avoid losing access",
        "Verify through the bank's official website or app",
        "Reply with your account number to confirm it's you",
        "Forward the message to a friend for a second opinion"
      ],
      correct: 1,
      explanation: "Banks don't threaten to lock your account over a message link. Always go directly to the bank's known app or official website instead of clicking a link in the message."
    },
    {
      question: "An email says you've won a lottery you never entered, and asks for a small fee to release the funds. What's the safest response?",
      options: [
        "Pay the fee since the prize is worth more",
        "Ask for proof first, then pay",
        "Delete or report the message — legitimate prizes never require a fee",
        "Reply asking them to reduce the fee"
      ],
      correct: 2,
      explanation: "You can't win a lottery you never entered, and real prizes never require an upfront 'release fee'. This is a classic advance-fee scam."
    },
    {
      question: "A text asks you to share the OTP you just received to 'verify your identity' for a delivery. What should you do?",
      options: [
        "Share it, since it's just for a delivery",
        "Never share it — no legitimate service asks for your OTP this way",
        "Share only the last two digits",
        "Ask them to call you first, then share it"
      ],
      correct: 1,
      explanation: "An OTP is meant to stay private between you and the service that sent it. Anyone asking you to relay it elsewhere is trying to bypass that protection."
    },
    {
      question: "You get a well-paid remote job offer, but must pay a 'training fee' before starting. This is most likely:",
      options: [
        "A totally normal onboarding step",
        "A scam — legitimate employers do not charge you to be hired",
        "Fine, as long as the fee is small",
        "Only risky if paid by wire transfer"
      ],
      correct: 1,
      explanation: "Legitimate employers pay you — they don't require payment from you to start a job. Any upfront 'fee' for training, equipment or registration is a major red flag."
    },
    {
      question: "An unknown number says your package couldn't be delivered and asks you to click a link and pay $2.99. What's the best first step?",
      options: [
        "Click the link since the amount is small",
        "Check tracking directly through the courier's official app or website",
        "Reply \"STOP\" to the number",
        "Pay immediately to avoid delay"
      ],
      correct: 1,
      explanation: "Delivery scams rely on small, easy-to-approve fees. Go to the courier's official tracking tool directly instead of any link sent to you."
    },
    {
      question: "A message uses ALL CAPS, several exclamation marks, and phrases like 'ACT NOW!!!'. This formatting is:",
      options: [
        "A sign the sender is simply excited",
        "A common pressure tactic used to rush your decision-making",
        "Proof the message is safe",
        "Irrelevant to whether a message is a scam"
      ],
      correct: 1,
      explanation: "Urgent, shouted formatting is designed to trigger a fast, emotional reaction instead of careful thinking — a tactic used heavily in scam messages."
    },
    {
      question: "A message claims to be from a company's 'Security Department', but the sender address looks unfamiliar and generic. What should you do?",
      options: [
        "Trust it — it mentions a real company",
        "Independently verify through the company's official contact channel",
        "Reply asking them to prove who they are",
        "Forward your account details so they can 'check' it"
      ],
      correct: 1,
      explanation: "Anyone can type a real company's name into a message. Confirm requests through a phone number or site you found yourself — never through the contact details in the message."
    },
    {
      question: "A message offers a gift card for a 'quick survey', but first asks for your card number to 'verify eligibility'. This is:",
      options: [
        "Normal for survey rewards",
        "A red flag — real surveys don't need your card number",
        "Safe if the survey looks professional",
        "Only risky if the amount is large"
      ],
      correct: 1,
      explanation: "There's no legitimate reason a free survey reward would need your payment card number. This pattern is used purely to harvest card details."
    }
  ];

  let currentIndex = 0;
  let score = 0;
  let answered = false;
  let els = {};

  function cacheEls() {
    els = {
      questionView: document.getElementById('quizQuestionView'),
      resultView: document.getElementById('quizResultView'),
      question: document.getElementById('quizQuestion'),
      options: document.getElementById('quizOptions'),
      feedback: document.getElementById('quizFeedback'),
      verdict: document.getElementById('quizVerdict'),
      explanation: document.getElementById('quizExplanation'),
      nextBtn: document.getElementById('quizNextBtn'),
      progressFill: document.getElementById('quizProgressFill'),
      progressLabel: document.getElementById('quizProgressLabel'),
      resultScore: document.getElementById('quizResultScore'),
      resultTitle: document.getElementById('quizResultTitle'),
      resultMessage: document.getElementById('quizResultMessage'),
      retakeBtn: document.getElementById('quizRetakeBtn')
    };
  }

  function renderQuestion() {
    answered = false;
    const q = QUESTIONS[currentIndex];
    els.question.textContent = q.question;
    els.options.innerHTML = '';
    q.options.forEach((optionText, idx) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'quiz-option';
      btn.textContent = optionText;
      btn.addEventListener('click', () => selectAnswer(idx));
      els.options.appendChild(btn);
    });
    els.feedback.hidden = true;
    els.progressFill.style.width = `${(currentIndex / QUESTIONS.length) * 100}%`;
    els.progressLabel.textContent = `Question ${currentIndex + 1} of ${QUESTIONS.length}`;
  }

  function selectAnswer(idx) {
    if (answered) return;
    answered = true;
    const q = QUESTIONS[currentIndex];
    const buttons = [...els.options.querySelectorAll('.quiz-option')];
    const isCorrect = idx === q.correct;
    if (isCorrect) score += 1;

    buttons.forEach((btn, i) => {
      btn.disabled = true;
      if (i === q.correct) btn.classList.add('correct');
      else if (i === idx) btn.classList.add('incorrect');
    });

    els.verdict.textContent = isCorrect ? 'Correct!' : 'Not quite.';
    els.verdict.className = 'quiz-feedback-verdict ' + (isCorrect ? 'is-correct' : 'is-incorrect');
    els.explanation.textContent = q.explanation;
    els.nextBtn.textContent = currentIndex === QUESTIONS.length - 1 ? 'See Results' : 'Next Question';
    els.feedback.hidden = false;
  }

  function handleNext() {
    currentIndex += 1;
    if (currentIndex >= QUESTIONS.length) {
      showResults();
    } else {
      renderQuestion();
    }
  }

  function showResults() {
    els.progressFill.style.width = '100%';
    els.progressLabel.textContent = `Question ${QUESTIONS.length} of ${QUESTIONS.length}`;
    els.questionView.hidden = true;
    els.resultView.hidden = false;

    const total = QUESTIONS.length;
    els.resultScore.textContent = `${score} / ${total}`;

    let title, message;
    if (score >= total - 1) {
      title = 'Cyber Safety Champion';
      message = "Excellent instincts — you're spotting the same red flags SHIELD 2.0's detector looks for.";
    } else if (score >= total / 2) {
      title = 'Good Awareness';
      message = 'Solid grasp of the basics. Review the explanations above to sharpen a few remaining blind spots.';
    } else {
      title = 'Keep Practicing';
      message = 'Scam tactics can be subtle — revisit the Threat Library and Safety Tips, then try again.';
    }
    els.resultTitle.textContent = title;
    els.resultMessage.textContent = message;
  }

  function retake() {
    currentIndex = 0;
    score = 0;
    els.questionView.hidden = false;
    els.resultView.hidden = true;
    renderQuestion();
  }

  function init() {
    cacheEls();
    if (!els.question) return; // quiz markup not present on this page
    els.nextBtn.addEventListener('click', handleNext);
    els.retakeBtn.addEventListener('click', retake);
    renderQuestion();
  }

  return { init };
})();
