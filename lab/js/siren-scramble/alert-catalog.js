(function (global) {
  const SirenAlertCatalog = [
    {
      id: 'phish-intro',
      type: 'phishing',
      title: 'Phishing Pop-up',
      difficulty: 1,
      minLevel: 1,
      maxLevel: 5,
      timeBonus: 4,
      steps: [
        {
          id: 'verify-sender',
          label: 'Verify Sender',
          hint: 'Check the weird sender name before clicking anything.',
          arrow: 'left'
        }
      ],
      decoys: [
        { id: 'click-link', label: 'Click the Flashy Link', reaction: 'The link bursts into glitter smoke!' },
        { id: 'reply-password', label: 'Reply with Password', reaction: 'A cartoon lock shakes its head.' }
      ],
      ui: {
        message: {
          sender: 'space-mail@tr1cky.biz',
          subject: 'URGENT: Claim your prize now!!!',
          clue: 'Sender name looks odd & the link is misspelled.',
          body: 'Click now to keep your account safe! Totally real, promise.'
        },
        helper: 'Tap the magnifying glass to reveal a clue.'
      }
    },
    {
      id: 'phish-two-step',
      type: 'phishing',
      title: 'Phishing Pop-up',
      difficulty: 3,
      minLevel: 3,
      maxLevel: 5,
      timeBonus: 6,
      steps: [
        {
          id: 'verify-sender',
          label: 'Verify Sender',
          hint: 'Spot the mismatched address first.',
          arrow: 'up'
        },
        {
          id: 'report-popup',
          label: 'Report & Close',
          hint: 'Shut it down to stay safe!',
          arrow: 'right'
        }
      ],
      decoys: [
        { id: 'click-link', label: 'Click the Flashy Link', reaction: 'Confetti pop! But that was a trick link.' },
        { id: 'reply-password', label: 'Reply with Password', reaction: 'A cartoon lock shakes its head.' },
        { id: 'ask-hamster', label: 'Ask the Hamster', reaction: 'Hamster spins and shrugs.' }
      ],
      ui: {
        message: {
          sender: 'security@totally-safe.co',
          subject: 'Reset needed in 45 seconds',
          clue: 'Timer pressure and a wonky link preview.',
          body: 'We spotted a problem—click fast to fix it!'
        },
        helper: 'Two-step combo: verify, then report.'
      }
    },
    {
      id: 'password-leak',
      type: 'password',
      title: 'Password Leak Detected',
      difficulty: 2,
      minLevel: 2,
      maxLevel: 5,
      timeBonus: 5,
      steps: [
        {
          id: 'build-strong',
          label: 'Build Strong Password',
          hint: 'Use a number and a symbol; avoid common words.',
          arrow: 'down'
        }
      ],
      decoys: [
        { id: 'banana-patch', label: 'Deploy Banana Patch', reaction: 'Bananas fall from the sky. Cute, but not secure.' },
        { id: 'glitter-firewall', label: 'Glitter Firewall', reaction: 'Shimmering wall sparkles... and then fizzles.' }
      ],
      ui: {
        tiles: ['comet', 'password', '99', '!', 'shield', '#', 'dragon', '7', '*'],
        banned: ['password'],
        needsNumber: true,
        needsSymbol: true,
        targetLength: 3
      }
    },
    {
      id: 'password-two-step',
      type: 'password',
      title: 'Password Leak Contained',
      difficulty: 4,
      minLevel: 4,
      maxLevel: 5,
      timeBonus: 6,
      steps: [
        {
          id: 'build-strong',
          label: 'Build Strong Password',
          hint: 'Mix words + numbers + symbols.',
          arrow: 'down'
        },
        {
          id: 'lock-vault',
          label: 'Lock Vault',
          hint: 'Seal it with the vault lock.',
          arrow: 'left'
        }
      ],
      decoys: [
        { id: 'banana-patch', label: 'Deploy Banana Patch', reaction: 'Bananas fall from the sky. Cute, but not secure.' },
        { id: 'ask-hamster', label: 'Ask the Hamster', reaction: 'Hamster spins and shrugs.' }
      ],
      ui: {
        tiles: ['nebula', '42', '!', 'shield', '#', 'spark', '9', '?', 'jet'],
        banned: ['password'],
        needsNumber: true,
        needsSymbol: true,
        targetLength: 4
      }
    },
    {
      id: 'login-check',
      type: 'login',
      title: 'Suspicious Login',
      difficulty: 2,
      minLevel: 2,
      maxLevel: 5,
      timeBonus: 4,
      steps: [
        {
          id: 'block-login',
          label: 'Block Login',
          hint: 'The location looks unusual.',
          arrow: 'left'
        }
      ],
      decoys: [
        { id: 'allow-login', label: 'Allow Login', reaction: 'Alarm chirps politely—maybe not that one.' }
      ],
      ui: {
        clue: 'Login from Antarctica at 3:12 AM',
        helper: 'If it feels off, block it first.'
      }
    },
    {
      id: 'login-two-step',
      type: 'login',
      title: 'Suspicious Login',
      difficulty: 5,
      minLevel: 5,
      maxLevel: 5,
      timeBonus: 7,
      steps: [
        {
          id: 'block-login',
          label: 'Block Login',
          hint: 'Freeze it before anything else.',
          arrow: 'right'
        },
        {
          id: 'reset-password',
          label: 'Reset Password',
          hint: 'Reset after you block.',
          arrow: 'up'
        }
      ],
      decoys: [
        { id: 'allow-login', label: 'Allow Login', reaction: 'Alarm chirps politely—maybe not that one.' },
        { id: 'glitter-firewall', label: 'Glitter Firewall', reaction: 'Shimmering wall sparkles... and then fizzles.' }
      ],
      ui: {
        clue: 'Login from: Outer Space Station at 2:04 AM',
        helper: 'Block first, then reset.'
      }
    }
  ];

  const exported = { SirenAlertCatalog };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exported;
  } else {
    global.SirenAlertCatalog = SirenAlertCatalog;
  }
})(typeof window !== 'undefined' ? window : globalThis);
