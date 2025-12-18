# Attack Paths Module - Quick Start Guide

## 🚀 Get Started in 60 Seconds

### 1. Open the Module

```bash
# From frontend directory
open public/attacks.html
# Or navigate to: http://localhost:8080/attacks.html
```

### 2. Try It Out

1. Click **"Authorization Code Interception"** from the sidebar
2. Click **"Next"** to step through the attack
3. Watch the animated diagram show how the attack works
4. Review the **"How to Prevent This Attack"** section

That's it! You're now seeing an OAuth 2.0 attack visualization.

---

## 📁 File Structure

```
frontend/
├── public/
│   ├── attacks.html              ← Main page (open this)
│   ├── css/
│   │   └── attacks.css           ← Diagram styles
│   └── js/
│       ├── attack-scenarios.js   ← Attack definitions (edit to add new)
│       └── attacks.js            ← Animation controller
├── ATTACK_PATHS.md               ← Full documentation
├── ATTACK_MODULE_SUMMARY.md      ← Implementation details
├── EXAMPLE_NEW_ATTACK.js         ← Template for adding attacks
└── QUICK_START.md                ← This file
```

---

## 🎯 What's Included

### 6 Attack Scenarios (All for Authorization Code Flow)

| Attack | Severity | Category | Steps |
|--------|----------|----------|-------|
| Code Interception | High | Code Flow | 5 |
| Redirect URI Manipulation | **Critical** | Code Flow | 5 |
| Token Leakage (Storage) | High | Token Security | 5 |
| Token Leakage (Logs) | Medium | Token Security | 5 |
| Scope Escalation | Medium | Authorization | 5 |
| CSRF on Callback | High | Code Flow | 5 |

**Total**: 30 animated steps with diagrams and mitigations

---

## 🎨 Visual Features

### Diagram Elements

- **👤 User** (blue circle, left side)
- **💻 Client** (purple circle, right side)
- **🔐 Auth Server** (yellow circle, top)
- **🗄️ Resource Server** (green circle, bottom)
- **💀 Attacker** (red circle, dynamic position)

### Arrow Types

- **Blue arrow** → Normal OAuth flow
- **Red arrow** → Attack vector
- **Purple arrow** → Compromised access
- **Dashed line** → Intercepted/injected communication

### Node States

- **Active** (glowing border) - Currently involved
- **Attack** (red pulsing) - Under attack
- **Compromised** (purple) - Breached
- **Faded** (transparent) - Inactive

---

## ➕ Add Your Own Attack (5 Minutes)

### Step 1: Open attack-scenarios.js

```bash
open public/js/attack-scenarios.js
```

### Step 2: Copy This Template

```javascript
{
  id: 'my_attack',
  title: 'My Attack Name',
  category: 'Code Flow Attacks',
  severity: 'high', // 'critical', 'high', or 'medium'
  description: 'What this attack does',
  steps: [
    { text: 'Step 1', highlight: 'normal' },
    { text: 'Step 2', highlight: 'attack' },
    { text: 'Step 3', highlight: 'compromised' }
  ],
  diagramActions: [
    {
      step: 0,
      action: 'showFlow',
      nodes: ['user', 'authServer'],
      arrows: [
        { from: 'user', to: 'authServer', label: 'Login', color: 'normal' }
      ]
    },
    {
      step: 1,
      action: 'showAttack',
      nodes: ['attacker', 'authServer'],
      arrows: [
        { from: 'attacker', to: 'authServer', label: 'Exploit', color: 'attack' }
      ]
    },
    {
      step: 2,
      action: 'showCompromised',
      nodes: ['attacker', 'resourceServer'],
      arrows: [
        { from: 'attacker', to: 'resourceServer', label: 'Access', color: 'compromised' }
      ]
    }
  ],
  mitigations: [
    'How to prevent this attack',
    'Another prevention method'
  ]
}
```

### Step 3: Add to ATTACK_SCENARIOS Array

```javascript
const ATTACK_SCENARIOS = [
  // ... existing attacks ...

  // YOUR NEW ATTACK HERE
  {
    id: 'my_attack',
    // ... your attack definition
  }
];
```

### Step 4: Reload and Test

Refresh `attacks.html` - your new attack appears in the sidebar!

---

## 🔍 Detailed Examples

See **EXAMPLE_NEW_ATTACK.js** for:
- Complete attack template with comments
- Common attack patterns (MITM, phishing, token theft)
- All available node/arrow configurations
- Testing checklist

---

## 🛠️ Customization Options

### Change Severity Colors

Edit `attacks.css`:

```css
/* Critical attacks */
.severity-critical {
  background: #dc2626; /* Red */
}

/* High severity */
.severity-high {
  background: #f59e0b; /* Orange */
}

/* Medium severity */
.severity-medium {
  background: #eab308; /* Yellow */
}
```

### Adjust Animation Speed

Edit `attacks.js`:

```javascript
anime({
  targets: path,
  strokeDashoffset: [pathLength, 0],
  duration: 800, // Change this (milliseconds)
  easing: 'easeInOutQuad'
});
```

### Change Node Positions

Edit `positionNodes()` in `attacks.js`:

```javascript
const positions = {
  user: { x: width * 0.15, y: height * 0.5 }, // 15% from left
  client: { x: width * 0.85, y: height * 0.5 }, // 85% from left
  // ... adjust percentages
};
```

---

## 🐛 Troubleshooting

### Arrows Not Showing

**Problem**: Diagram loads but no arrows appear
**Fix**: Open browser console, check for SVG errors

```javascript
// Debug: Log arrow rendering
console.log('Drawing arrow from', fromNode, 'to', toNode);
```

### Animations Jerky

**Problem**: Animations stutter or lag
**Fix**: Check if anime.js loaded

```bash
# In browser console:
typeof anime
# Should return: "function"
```

### Attack Not Listed

**Problem**: Added attack but it doesn't show in sidebar
**Fix**: Check JavaScript syntax

```bash
# Validate JSON syntax
node -e "require('./public/js/attack-scenarios.js')"
```

---

## 📚 Documentation

| File | Purpose |
|------|---------|
| **QUICK_START.md** | This file - get started fast |
| **ATTACK_PATHS.md** | Complete API reference and usage guide |
| **ATTACK_MODULE_SUMMARY.md** | Implementation details and design decisions |
| **EXAMPLE_NEW_ATTACK.js** | Template with patterns and examples |

---

## 🔗 Navigation

From the attack module, you can navigate to:

- **Normal Flow Demo** ([demo.html](./public/demo.html)) - See legitimate OAuth flow
- **User Portal** ([index.html](./public/index.html)) - Manage consents
- **Admin View** ([admin.html](./public/admin.html)) - Audit logs

All pages are linked in the top navigation bar.

---

## ⚡ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `→` | Next step |
| `←` | Previous step |
| `R` | Reset animation |
| `Esc` | Deselect attack |

*(Keyboard shortcuts require focus on diagram area)*

---

## 📊 Statistics

- **Total Code**: 2,432 lines
- **Attack Scenarios**: 6
- **Animated Steps**: 30
- **Mitigations**: 24
- **Dependencies**: 2 (Alpine.js, Anime.js)
- **Load Time**: <100ms

---

## 🎓 Learning Path

### Beginner

1. Open attacks.html
2. Try "Redirect URI Manipulation" (simplest)
3. Read the mitigations
4. Compare with normal flow in demo.html

### Intermediate

1. Try all 6 attacks
2. Understand the step-by-step progression
3. Review ATTACK_PATHS.md
4. Modify existing attack (change label text)

### Advanced

1. Add a new attack using EXAMPLE_NEW_ATTACK.js
2. Create custom animation sequences
3. Add attack categories
4. Build exportable reports

---

## 💡 Tips

1. **Start with Critical severity** - Most impactful attacks
2. **Use dashed arrows** for intercepted/injected communication
3. **Keep steps to 5 max** - Easier to follow
4. **Test on mobile** - Diagram is responsive
5. **Read mitigations** - That's where the learning happens

---

## ✅ Next Steps

- [ ] Try all 6 attacks
- [ ] Read ATTACK_PATHS.md for full docs
- [ ] Add a custom attack
- [ ] Share with your team
- [ ] Use in security training

---

## 🤝 Contributing

To add more attacks to the collection:

1. Follow the template in EXAMPLE_NEW_ATTACK.js
2. Test thoroughly (all steps animate correctly)
3. Include 3-5 mitigations
4. Ensure severity is accurate
5. Document any new node patterns

---

## 📞 Support

- **Documentation Issues**: See ATTACK_PATHS.md
- **Code Issues**: Check browser console
- **Animation Issues**: Verify anime.js loaded
- **General Questions**: Review ATTACK_MODULE_SUMMARY.md

---

**Ready to explore OAuth 2.0 security vulnerabilities? Open [attacks.html](./public/attacks.html) now!**
