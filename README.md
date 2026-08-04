# VulnNotes

A deliberately vulnerable React + Node full-stack benchmark for autonomous security-fix agents.

## Tech stack
- Frontend: React 18 + Vite
- Backend: Node + Express + LowDB

## Run locally
```bash
npm install
npm run dev
```

## Run tests
```bash
npm test
```

## Security hardening
See PR #2 for applied fixes: Helmet, express-validator, CSRF protection, rate-limiting, DOMPurify, CORS restriction, IDOR prevention, password hashing, and privilege escalation prevention.

## License
MIT
