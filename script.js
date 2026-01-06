// Utility: SHA-1 hash in hex (browser)
async function sha1(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

// Strength elements
const passwordInput = document.getElementById("password");
const strengthBar = document.getElementById("strength-bar");
const strengthText = document.getElementById("strength-text");
const strengthSuggestions = document.getElementById("strength-suggestions");

// Breach elements
const breachPasswordInput = document.getElementById("breach-password");
const checkPasswordBreachBtn = document.getElementById("check-password-breach");
const passwordBreachResult = document.getElementById("password-breach-result");

// --- Tight password policy config ---
const MIN_LENGTH = 12;         // minimum length to be acceptable
const STRONG_LENGTH = 16;      // length to be "very strong"
const MIN_ZXCVBN_SCORE = 3;    // 0–4, require 3+ to be "OK"

// Check character diversity
function analyzeChars(pwd) {
  let lower = false;
  let upper = false;
  let digit = false;
  let symbol = false;

  for (const ch of pwd) {
    if (/[a-z]/.test(ch)) lower = true;
    else if (/[A-Z]/.test(ch)) upper = true;
    else if (/[0-9]/.test(ch)) digit = true;
    else symbol = true;
  }

  const typesCount = [lower, upper, digit, symbol].filter(Boolean).length;
  return { lower, upper, digit, symbol, typesCount };
}

// Map "policy score" to label and color
function policyLabel(pwd, zResult) {
  if (!pwd) {
    return { label: "", color: "#22c55e", width: "0%" };
  }

  const length = pwd.length;
  const chars = analyzeChars(pwd);

  // Build suggestions from policy + zxcvbn feedback
  const suggestions = [];

  if (length < MIN_LENGTH) {
    suggestions.push(`Use at least ${MIN_LENGTH} characters.`);
  }
  if (chars.typesCount < 3) {
    suggestions.push("Use a mix of lowercase, uppercase, numbers, and symbols (at least 3 types).");
  }
  if (zResult.score < MIN_ZXCVBN_SCORE) {
    suggestions.push("Avoid common words, names, or patterns.");
  }

  if (zResult.feedback.warning) {
    suggestions.push(zResult.feedback.warning);
  }
  if (zResult.feedback.suggestions && zResult.feedback.suggestions.length) {
    suggestions.push(...zResult.feedback.suggestions);
  }

  // Decide label based on all conditions
  let label;
  let color;
  let width;

  if (length < MIN_LENGTH || chars.typesCount < 2 || zResult.score <= 1) {
    label = "Too weak";
    color = "#ef4444";
    width = "20%";
  } else if (
    length >= MIN_LENGTH &&
    chars.typesCount >= 2 &&
    zResult.score === 2
  ) {
    label = "Weak";
    color = "#f97316";
    width = "40%";
  } else if (
    length >= MIN_LENGTH &&
    chars.typesCount >= 3 &&
    zResult.score === 3
  ) {
    label = "Strong";
    color = "#22c55e";
    width = "70%";
  } else if (
    length >= STRONG_LENGTH &&
    chars.typesCount >= 3 &&
    zResult.score === 4
  ) {
    label = "Very strong";
    color = "#22c55e";
    width = "100%";
  } else {
    // Fallback "Medium"
    label = "Medium";
    color = "#eab308";
    width = "60%";
  }

  return { label, color, width, suggestions };
}

// Update strength meter using tighter rules
passwordInput.addEventListener("input", () => {
  const pwd = passwordInput.value;
  if (!pwd) {
    strengthBar.style.width = "0%";
    strengthText.textContent = "";
    strengthSuggestions.innerHTML = "";
    return;
  }

  const zResult = zxcvbn(pwd); // zxcvbn loaded from CDN
  const meta = policyLabel(pwd, zResult);

  strengthBar.style.width = meta.width;
  strengthBar.style.background = meta.color;

  const guesses = zResult.guesses.toLocaleString();
  strengthText.textContent = `Strength: ${meta.label} (zxcvbn score ${zResult.score}/4, guesses ~${guesses})`;

  strengthSuggestions.innerHTML = "";
  const uniqueSuggestions = [...new Set(meta.suggestions)];
  uniqueSuggestions.forEach(s => {
    if (!s) return;
    const li = document.createElement("li");
    li.textContent = s;
    strengthSuggestions.appendChild(li);
  });
});

// Password breach check using free Pwned Passwords k-Anonymity API
checkPasswordBreachBtn.addEventListener("click", async () => {
  const pwd = breachPasswordInput.value;
  passwordBreachResult.textContent = "";

  if (!pwd) {
    passwordBreachResult.textContent = "Enter a password to check.";
    return;
  }

  passwordBreachResult.style.color = "#e2e8f0";
  passwordBreachResult.textContent = "Checking...";

  try {
    const hash = await sha1(pwd);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();

    const lines = text.split("\n");
    let count = 0;
    for (const line of lines) {
      const [hashSuffix, occurrences] = line.split(":");
      if (hashSuffix.trim() === suffix) {
        count = parseInt(occurrences.trim(), 10);
        break;
      }
    }

    if (count > 0) {
      passwordBreachResult.style.color = "#ef4444";
      passwordBreachResult.textContent =
        `This password has appeared in breaches ${count.toLocaleString()} times. Do not use it.`;
    } else {
      passwordBreachResult.style.color = "#22c55e";
      passwordBreachResult.textContent =
        "This password was not found in the breached password database.";
    }
  } catch (err) {
    console.error(err);
    passwordBreachResult.style.color = "#f97316";
    passwordBreachResult.textContent = "Error checking password. Try again later.";
  }
});
