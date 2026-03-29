# ToolVault

A web-based security tool management dashboard. ToolVault connects to GitHub (and future integrations like DefectDojo, OWASP ZAP, etc.) to give your team a central place to browse repositories, track tooling, and manage access.

## Architecture Overview

```
app/
  backend/       Express + SQLite API server (port 3001)
  frontend/      React + Vite SPA (port 5173)
```

The frontend is a React single-page application that talks to the backend via REST API. The backend proxies external services (like GitHub) so that API tokens stay on the server and are never exposed to the browser.

## Quick Start (Full Stack)

You need two terminal windows — one for the backend, one for the frontend.

### Terminal 1: Backend

```bash
cd backend

# Install dependencies
npm install

# Create your environment file
cp .env.example .env

# Edit .env — at minimum, set JWT_SECRET to any random string
# (GitHub settings can be configured later from the web UI)

# Start the backend
npm run dev
```

### Terminal 2: Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start the frontend
npm run dev
```

### Open the App

1. Go to **http://localhost:5173** in your browser
2. Log in with the default admin account:
   - **Username:** `admin`
   - **Password:** `admin123`
3. Go to the **Integrations** page (in the sidebar under "Admin")
4. Enter your GitHub organization name or personal username
5. Enter a GitHub personal access token (classic, with `repo` scope)
6. Click **Save settings**, then **Test connection**
7. Head to the **Dashboard** or **Search** page to see your repos

## GitHub Token Setup

ToolVault needs a GitHub personal access token to fetch repository data.

1. Go to https://github.com/settings/tokens
2. Click **"Generate new token (classic)"**
3. Give it a name (e.g., "ToolVault")
4. Select scopes:
   - `repo` — for private + public repos
   - `public_repo` — for public repos only
5. Click **Generate token** and copy it
6. Paste it into the Integrations page in ToolVault

**Organizations vs. personal accounts:** ToolVault works with both. If you enter a GitHub organization name (like `google`), it fetches that org's repos. If you enter a personal username, it fetches that user's repos. For private repos under a personal account, the token must have the full `repo` scope.

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | React 19 | UI components and state |
| Routing | react-router-dom 7 | Client-side page navigation |
| Build Tool | Vite 8 | Fast dev server and production builds |
| Backend | Express 4 | REST API server |
| Database | SQLite (better-sqlite3) | User accounts and settings storage |
| Auth | JWT (jsonwebtoken + bcryptjs) | Stateless token-based authentication |

## Features

- **Dashboard** — KPI cards (total repos, stars, forks, open issues), language breakdown chart, and recently updated repos
- **Search** — Full-text search across repos with language and topic filters
- **User Management** (admin) — Create and delete user accounts, assign roles
- **Integrations** (admin) — Configure GitHub org/username and token from the web UI, test connections
- **Extensible** — Built to add more integrations (DefectDojo, OWASP ZAP, etc.) with commented guide templates in every file

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |

**Change the default password in production.** The admin account is created automatically when the database is first initialized.

## Project Structure

```
app/
  backend/
    server.js             - Express entry point, route registration
    database.js           - SQLite setup, tables, default data
    .env.example          - Environment variable template
    middleware/
      auth.js             - JWT auth (requireAuth, requireAdmin)
    routes/
      auth.js             - Login, register, user endpoints
      github.js           - GitHub API proxy (repos, search)
      settings.js         - Admin settings endpoints

  frontend/
    src/
      App.jsx             - Route definitions, auth state
      components/
        Navbar.jsx        - Sidebar navigation
      pages/
        LoginPage.jsx     - Login form
        DashboardPage.jsx - Stats and charts
        SearchPage.jsx    - Repo search
        AdminPage.jsx     - User management
        IntegrationsPage.jsx - GitHub config
      services/
        api.js            - HTTP client with auth
        github.js         - GitHub data helpers
```

## How to Add a New Integration

ToolVault is designed to be extended with new tool integrations. Every key file contains a `HOW TO ADD` comment block with step-by-step instructions. Here's the overall process:

### Backend

1. **Add default settings** in `database.js` → `defaultSettings` object
2. **Create a route file** (copy `routes/github.js` as a template)
3. **Register routes** in `server.js`
4. **Add settings** to `routes/settings.js` GET/PUT handlers

### Frontend

5. **Create a service file** in `services/` for API calls
6. **Create a page component** in `pages/` for the UI
7. **Add the route** in `App.jsx`
8. **Add a nav link** in `components/Navbar.jsx`
9. **Add a settings section** to `IntegrationsPage.jsx`

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `"doctype is not valid JSON"` on login | Missing `.env` file or `JWT_SECRET` not set | Copy `.env.example` to `.env`, fill in `JWT_SECRET` |
| `"GitHub organization not found"` | Wrong org name or no token | Check the Integrations page. For personal accounts, use your GitHub username. |
| Only public repos show up | Token has `public_repo` scope only | Generate a new classic token with the full `repo` scope |
| `better-sqlite3` won't install | Missing native build tools | On Windows: `npm install --global windows-build-tools` |
| Frontend shows blank page | Backend isn't running | Start the backend first (`npm run dev` in `backend/`) |
| Port already in use | Another process is using 3001 or 5173 | Stop the other process, or change `PORT` in `.env` |

## For Developers

- The codebase uses **ES modules** (`import`/`export`) throughout
- All API responses are **JSON** — the backend includes a catch-all error handler to prevent HTML error pages
- The backend uses **camelCase** field names in API responses (the `normalizeRepo` function converts from GitHub's snake_case)
- Auth tokens are stored in **sessionStorage** (cleared when the tab closes)
- The SQLite database file (`toolvault.sqlite`) is auto-created on first startup and gitignored

See the individual READMEs in `backend/` and `frontend/` for more detailed documentation.
