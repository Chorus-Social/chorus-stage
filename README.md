# Chorus Stage

<p align="center">
  <img src="https://raw.githubusercontent.com/Chorus-Social/.github/refs/heads/main/branding/web/Glow_Wireframe_Banner_XL.webp" alt="Chorus Network Banner">
</p>

Welcome to **Chorus Stage**, the core backend network powering the Chorus social project. This API-first service is the heart that connects everything — managing user identities, communities, posts, votes, and moderation, all with a strong focus on user anonymity.

---

## About Chorus Stage

Chorus Stage is the backend API for the Chorus Network. It exposes a clean, open set of API endpoints that empower clients and users to:

- Create, join, and leave communities  
- Post new content and reply with comments  
- Register new users and update user profiles securely  
- Cast votes, participate in the democratic moderation process  
- Handle community moderation openly and transparently  

…and much more as development progresses.

The network is built to be secure, with all communications encrypted end-to-end and sensitive data stored securely. However, Chorus is fundamentally designed to provide **anonymity** rather than traditional notions of privacy or security. Users are identified solely by unique, cryptographic public keys (ed25519) that are exclusive to the Chorus network. Each client generates a new key-pair locally during account creation to ensure keys are not reused elsewhere, preventing cross-platform fingerprinting and preserving user anonymity. No emails, passwords, or personal information are required or stored. Privacy is achieved through this strong anonymity model — no personal data is linked or retained.

---

## The Bigger Picture

Chorus Stage is one essential component of the larger Chorus ecosystem, which includes:

- **Chorus Voice**: The upcoming official client app for iOS, Android, and web platforms  
- **Chorus Audience**: A simple, read-only web viewer acting as the public landing page and content gateway  

Together, these modules aim to build a genuine alternative social platform grounded in true anonymity, community control, and open development.

---

## Getting Started

If you're here, you're part of the journey at an early but exciting stage. Here's how to dive in:

- Check out the [wiki](https://github.com/Chorus-Social/chorus-stage/wiki) for detailed API docs, development guides, and design principles  
- Explore the project boards for current tasks and future plans  
- Join the conversation by opening issues or contributing code  
- Keep an eye on our open calls for feedback and ideas—your voice shapes Chorus  

---

## Documentation

- API overview: `docs/api/overview.md`
- Authentication: `docs/api/auth.md`
- Error semantics: `docs/api/errors.md`
- Proof-of-Work design: `docs/architecture/pow.md`
- Moderation: `docs/moderation.md`
- System and transparency: `docs/api/system.md`

For a quick tour of the runtime agents and responsibilities, see `AGENTS.md`.

---

## Security

Security and cryptography details are summarized in `SECURITY.md`, including
the server threat model, primitives in use, PoW construction, and our audit
roadmap. End-to-end encryption for messaging happens on clients; the server
stores opaque ciphertext and optional protocol headers.

---

## Contributing and Roadmap

We welcome contributions! Read `CONTRIBUTING.md` to get started and see
`ROADMAP.md` for near-term priorities and stretch goals.

---

## Core Principles Behind Chorus Stage

- 🕵️‍♂️ **Anonymity First**: Users are identified only by unique, network-exclusive cryptographic keys generated locally on clients, never by personal data or reused accounts.  
- 🔒 **Security by Encryption**: Communications are encrypted end-to-end, and all sensitive information is securely stored.  
- 🗳️ **Decentralized Democracy**: Community moderation is transparent and governed by users—no secret rules or moderators.  
- 📖 **Open API**: Every feature is accessible and documented, encouraging openness and extensibility.  
- ✨ **Transparency**: Development and moderation happen in the open for full accountability.  

---

## Join Our Chorus

This project welcomes those who seek a social space that respects anonymity and democratic participation. Whether you’re a developer, user, or digital rights advocate, here’s your invitation.

**Speak your mind. Find your tune. Join our Chorus.**
