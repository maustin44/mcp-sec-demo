# ToolVault Backend

Express + SQLite API server that handles authentication, GitHub integration, and admin settings for the ToolVault security dashboard.

## Prerequisites

- **Node.js** v18 or higher (v20+ recommended)
- **npm** (comes with Node.js)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Create your environment file
cp .env.example .env

# 3. Edit .env and fill in your values (see Environment Variables below)

# 4. Start the dev server (auto-restarts on file changes)
npm run dev
```

The server starts on **http://localhost:3001** by default.

To verify it's running, visit: http://localhost:3001/api/health

## Environment Variables

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | Any random string (16+ characters) used to sign login tokens and encrypt stored secrets. Make it long and hard to guess. |
| `GITHUB_TOKEN` | No | A GitHub personal access token (classic). Use `repo` scope for private repos, or `public_repo` for public only. Generate one at https://github.com/settings/tokens |
| `GITHUB_ORG` | No | The GitHub organization name or personal username whose repos will be displayed. |
| `PORT` | No | Port the server listens on. Defaults to `3001`. The frontend expects `3001`. |

**Note:** `GITHUB_TOKEN` and `GITHUB_ORG` are only needed for the initial seed. After the first startup, admins can change these values from the Integrations page in the web UI (the database values take priority over `.env`).

## Default Login

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |

The default admin account is created automatically on first startup. **Change the default password in production.**

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start with auto-restart on file changes (development) |
| `npm start` | Start without auto-restart (production) |

## API Endpoints

### Authentication (`/api/auth`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | No | Log in with username + password, returns a JWT token |
| POST | `/api/auth/register` | Admin | Create a new user account |
| GET | `/api/auth/me` | Yes | Get the currently logged-in user's info |
| GET | `/api/auth/users` | Admin | List all user accounts |
| DELETE | `/api/auth/users/:id` | Admin | Delete a user account |

### GitHub (`/api/github`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/github/repos` | Yes | List all repos for the configured org/user |
| GET | `/api/github/repos/search?q=keyword` | Yes | Search repos by name, description, or topic |

### Settings (`/api/settings`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings/integrations` | Admin | Get current integration config (token is masked) |
| PUT | `/api/settings/integrations` | Admin | Update GitHub org and/or token |
| POST | `/api/settings/integrations/test` | Admin | Test the GitHub connection |

### Health Check

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Returns `{ status: "ok" }` if the server is running |

## Project Structure

```
backend/
  server.js                     - Entry point. Registers routes and security middleware.
  database.js                   - SQLite setup, table creation, default data seeding.
  .env                          - Your local environment variables (not committed to git).
  .env.example                  - Template showing all available env vars.
  middleware/
    auth.js                     - JWT verification (requireAuth) and role check (requireAdmin).
    rateLimiter.js              - Rate limiting for login and API endpoints.
    securityHeaders.js          - HTTP security headers (XSS, clickjacking, MIME).
  utils/
    crypto.js                   - AES-256-GCM encryption/decryption for stored secrets.
  routes/
    auth.js                     - Login, register, user management endpoints.
    github.js                   - GitHub API proxy. Fetches repos using the stored token.
    settings.js                 - Admin endpoints to read/update integration settings.
    _integration-template.js    - Copy-paste template for adding new integrations.
```

## Security Practices

This backend follows security best practices for a production-grade application:

### Passwords
- Hashed with **bcrypt** using **12 salt rounds** (OWASP recommended minimum)
- Passwords require a minimum of **8 characters**
- Password hashes are never returned in API responses
- Login returns the same error for wrong username and wrong password (prevents username enumeration)

### API Tokens & Secrets
- Encrypted with **AES-256-GCM** before being stored in the database
- Encryption key derived from `JWT_SECRET` using **PBKDF2** (100,000 iterations)
- Decrypted only when needed for API calls (never sent to the frontend)
- Frontend only receives a masked preview (first 8 + last 4 characters)
- Backward-compatible: plaintext values from before encryption was added are handled gracefully

### Authentication
- **JWT tokens** expire after 8 hours
- Server validates `JWT_SECRET` exists and warns if it's too short on startup
- Tokens are stored in **sessionStorage** (cleared when browser tab closes)

### Rate Limiting
- **Login:** 5 attempts per 15 minutes per IP (prevents brute-force attacks)
- **API:** 100 requests per minute per IP (prevents abuse)
- Rate limit headers (`X-RateLimit-Remaining`) sent on every response

### HTTP Security Headers
- `X-Content-Type-Options: nosniff` — Prevents MIME type sniffing
- `X-Frame-Options: DENY` — Prevents clickjacking
- `X-XSS-Protection: 1; mode=block` — Enables browser XSS filter
- `Referrer-Policy: strict-origin-when-cross-origin` — Limits referrer leakage
- `Cache-Control: no-store` — Prevents caching of sensitive API responses
- `X-Powered-By` removed — Hides Express framework fingerprint

### Input Validation
- Username: 3–50 characters, alphanumeric + hyphens/underscores only
- Password: 8–128 characters
- Organization name: max 100 characters, alphanumeric + hyphens/underscores
- Token: max 500 characters
- JSON body size limited to 1MB
- User ID parameters validated as numbers

### What's NOT Included (consider for production deployment)
- HTTPS (use a reverse proxy like nginx or deploy behind a load balancer)
- CSRF protection (not needed for API-only backends using Bearer tokens)
- Database encryption at rest (SQLite file-level; consider SQLCipher for full encryption)
- Audit logging (who changed what settings, when)
- Password change/reset functionality

## Database

The backend uses **SQLite** via the `better-sqlite3` package. The database file (`toolvault.sqlite`) is created automatically on first startup in the backend folder.

**Tables:**

- `users` — User accounts (username, bcrypt-hashed password, role)
- `settings` — Key-value store for integration config (tokens are AES-encrypted)

To reset the database, stop the server and delete `toolvault.sqlite`, then restart. A fresh database with the default admin account will be created.

## How to Add a New Integration (Step-by-Step)

Template files are provided to make adding new integrations fast. Here's the full process using DefectDojo as an example:

### Backend (4 steps)

**Step 1: Add default settings** in `database.js`:
```js
const defaultSettings = {
  github_org: process.env.GITHUB_ORG || '',
  github_token: process.env.GITHUB_TOKEN || '',
  defectdojo_url: process.env.DEFECTDOJO_URL || '',       // ← add
  defectdojo_api_key: process.env.DEFECTDOJO_API_KEY || '', // ← add
}
```

**Step 2: Copy the template** and customize it:
```bash
cp routes/_integration-template.js routes/defectdojo.js
# Then find-and-replace TOOL_NAME → DefectDojo, etc.
```

**Step 3: Register the secret key** in `routes/settings.js`:
```js
const SECRET_KEYS = [
  'github_token',
  'defectdojo_api_key',  // ← add (will be auto-encrypted in DB)
]
```
Also add fields to the GET and PUT handlers in the same file.

**Step 4: Register the routes** in `server.js`:
```js
import defectdojoRoutes from './routes/defectdojo.js'
app.use('/api/defectdojo', defectdojoRoutes)
```

### Frontend (4 steps)

**Step 5: Copy the service template:**
```bash
cp src/services/_service-template.js src/services/defectdojo.js
# Update the API paths to match your backend routes
```

**Step 6: Copy the page template:**
```bash
cp src/pages/_PageTemplate.jsx src/pages/DefectDojoPage.jsx
# Customize the columns, imports, and display
```

**Step 7: Add the route** in `App.jsx`:
```jsx
import DefectDojoPage from './pages/DefectDojoPage'
// Inside <Routes>:
<Route path="/defectdojo" element={isLoggedIn ? <DefectDojoPage /> : <Navigate to="/login" />} />
```

**Step 8: Add a nav link** in `components/Navbar.jsx`

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `"doctype is not valid JSON"` on login | Your `.env` file is missing or `JWT_SECRET` is not set. Copy `.env.example` to `.env` and fill it in. |
| `"GitHub organization not found"` | The org name is wrong, or the token doesn't have access. Check the Integrations page. For personal accounts, enter your GitHub username. |
| Can only see public repos | Your token only has `public_repo` scope. Generate a new classic token with the full `repo` scope to see private repos. |
| `better-sqlite3` install fails | You may need Python and a C++ compiler. On Windows, run `npm install --global windows-build-tools` first. |
| Port 3001 already in use | Either stop the other process on 3001, or change `PORT` in your `.env` file. |
| "Too many login attempts" | Rate limiter triggered. Wait 15 minutes or restart the server. |
| Token decryption warning on startup | Safe to ignore if you recently changed `JWT_SECRET`. Re-save settings to re-encrypt with the new key. |
