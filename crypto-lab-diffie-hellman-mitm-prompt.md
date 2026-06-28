# Prompt: Create "crypto-lab-diffie-hellman-mitm" Demo

You are an expert cryptography educator and frontend developer who creates high-quality, focused, interactive browser-based educational tools.

## Project Goal
Create a new standalone browser demo called **Diffie-Hellman + Man-in-the-Middle** that helps students deeply understand why the Diffie-Hellman key exchange is secure against passive attackers but vulnerable to active man-in-the-middle attacks.

## Why This Is Valuable for Students
Diffie-Hellman is one of the most fundamental public-key protocols taught in cryptography courses, yet many students finish courses without a clear mental model of:
- How two parties can agree on a shared secret over an insecure channel
- Why a passive eavesdropper cannot easily recover the secret (discrete logarithm problem)
- Why an *active* attacker who can modify messages can completely break the protocol (classic MITM)

This demo should make these concepts intuitive through live interaction rather than just equations or static diagrams. It addresses a common gap between theoretical understanding and practical intuition.

## Learning Objectives
By the end of using this demo, a student should be able to:
- Explain how Diffie-Hellman allows two parties to derive the same shared secret
- Demonstrate why a passive attacker cannot efficiently compute the shared secret
- Show how an active man-in-the-middle attacker can impersonate both parties and establish separate keys with each
- Understand the critical importance of authentication (signatures, certificates, etc.) when using DH
- Describe the difference between passive and active attacks on key exchange

## Required Sections & Flow

### 1. Quick Explanation (Top)
- Short, clear explanation of the Diffie-Hellman protocol using small numbers or visual steps.
- Highlight the mathematical foundation (discrete logarithm problem) without requiring deep number theory.

### 2. Passive Attacker Scenario (Interactive)
- Two parties (Alice and Bob) perform normal Diffie-Hellman.
- A passive eavesdropper (Eve) can see all messages.
- Show that Eve cannot efficiently compute the shared secret (even with small numbers for illustration).
- Include controls to adjust parameter sizes and show computational difficulty growth.

### 3. Active Man-in-the-Middle Attack (Main Interactive Section)
- Allow the user to enable an active MITM attacker.
- Show step-by-step how the attacker intercepts and replaces public values.
- Demonstrate that Alice and Bob end up with *different* shared secrets, each unknowingly shared with the attacker.
- Visualize the three separate keys that exist after the attack.

### 4. "What Breaks" Comparison
- Side-by-side view:
  - Without authentication → MITM succeeds
  - With signatures / certificates → MITM is detected or prevented
- Simple illustration of how real protocols (TLS, Signal, SSH) add authentication to DH.

### 5. Key Takeaways
- Clear summary of when DH is safe and when it is not.
- Connection to real-world protocols that use authenticated Diffie-Hellman.

## Technical Preferences
- Browser-native (HTML + TypeScript/JavaScript). WASM is acceptable if it improves the experience but not required.
- Use small numbers by default for clarity, with an option to switch to larger (more realistic) parameters.
- Clean, focused, educational aesthetic consistent with crypto-lab.systemslibrarian.dev demos.
- Strong emphasis on visualization and step-by-step interaction.
- Self-contained where possible.

## Relationship to Existing Work
- This should complement (not duplicate) any existing key exchange overviews in Crypto Lab.
- It can link to more advanced authenticated key exchange demos (e.g., OPAQUE, X3DH, Noise) if relevant.
- Keep the focus narrow: classic unauthenticated Diffie-Hellman + MITM vulnerability.

## Output Requested
Please provide:
1. A recommended final display title for the demo page
2. High-level architecture and component breakdown
3. Key interactive elements and how they should behave
4. Suggested visualizations and UI layout
5. Any important security or pedagogical notes to include
6. Potential technical challenges and how to address them

Start with the proposed structure, then we can iterate on implementation details.
