# Mohammed Al-Kasmi Educational Platform

A private, full-stack educational platform for Mohammed Al-Kasmi's English-language students.

## Stack

- Node.js + Express
- SQLite + better-sqlite3
- Server-side sessions stored in SQLite
- bcrypt password hashing
- Helmet security headers
- Rate-limited login
- Backend-enforced RBAC and student data isolation
- Responsive vanilla HTML/CSS/JS frontend

## Run on Replit

1. Import this project into Replit.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and set a strong `SESSION_SECRET`.
4. Run `npm start`.
5. Open the Replit web preview.

The database is created automatically at `data/platform.db` and seeded only when the database is empty.

## Demo credentials

These are for initial testing only. Change them immediately in a real deployment.

- Admin: `admin` / `Admin@12345!`
- Teacher: `teacher` / `Teacher@12345!`
- Student Ahmed: `ahmed` / `Student@12345!`
- Student Sara: `sara` / `Student@12345!`
- Student Omar: `omar` / `Student@12345!`

Passwords are never displayed by the application and are stored only as bcrypt hashes.

## Security model

There is no registration endpoint or registration UI. Only an authenticated ADMIN can create student/teacher accounts.

Every protected API checks the authenticated session and role server-side. Student grades and absences are filtered by the session user's ID; supplying another student's ID is rejected. Grade mutation routes are ADMIN-only. Teacher routes cannot mutate grades.

For production, set `COOKIE_SECURE=true` when HTTPS is enabled and use a long random `SESSION_SECRET`.

## Video storage

Lectures currently accept secure video URLs. The database and lecture API are deliberately structured around a `videoUrl` field so an object-storage provider can be added later without changing the student/teacher permissions model.

## Tests

Run:

```bash
npm test
```

The security tests cover login-only access, role restrictions, student isolation for grades/absences, teacher grade restrictions, and admin-only account/grade management.
