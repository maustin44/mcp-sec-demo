# ToolVault Frontend

React single-page application that provides the dashboard, repo search, user management, and integration settings UI for ToolVault.

## Prerequisites

- **Node.js** v18 or higher (v20+ recommended)
- **npm** (comes with Node.js)
- **ToolVault Backend** must be running on `http://localhost:3001` (see `../backend/README.md`)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Start the dev server
npm run dev
```

The app opens at **http://localhost:5173** in your browser.

**Important:** The backend must be running first, or API calls will fail. Start the backend in a separate terminal before starting the frontend.

## Available Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start the Vite dev server with hot reload |
| `npm run build` | Build for production (output goes to `dist/`) |
| `npm run preview` | Preview the production build locally |
| `npm run lint` | Run ESLint to check for code issues |

## Pages and Routes

| Route | Page | Access | Description |
|-------|------|--------|-------------|
| `/login` | LoginPage | Public | Log in with username and password |
| `/dashboard` | DashboardPage | Logged in | Overview with repo stats, language breakdown, and recent activity |
| `/search` | SearchPage | Logged in | Search and browse all repos with filters |
| `/admin` | AdminPage | Admin only | Create and manage user accounts |
| `/integrations` | IntegrationsPage | Admin only | Configure GitHub org/username and API token |

If you're not logged in, all routes redirect to `/login`. If you're not an admin, admin routes redirect to `/dashboard`.

## Project Structure

```
frontend/
  index.html               - HTML entry point (Vite injects the app here)
  vite.config.js            - Vite build configuration
  package.json              - Dependencies and scripts
  src/
    main.jsx                - App entry point, sets up React Router
    App.jsx                 - Route definitions and auth state management
    App.css                 - Layout styles (sidebar + main content)
    index.css               - Global styles (fonts, colors, resets)
    components/
      Navbar.jsx            - Sidebar navigation with links and logout
    pages/
      LoginPage.jsx         - Login form
      LoginPage.css
      DashboardPage.jsx     - Stats cards, language chart, recent repos
      DashboardPage.css
      SearchPage.jsx        - Repo search with filters and sorting
      SearchPage.css
      AdminPage.jsx         - User management (create, delete users)
      AdminPage.css
      IntegrationsPage.jsx  - GitHub integration settings form
      IntegrationsPage.css
    services/
      api.js                - HTTP client with JWT token management
      github.js             - GitHub-specific API calls and data helpers
```

## How the Frontend Talks to the Backend

All API calls go through `src/services/api.js`, which provides an `apiFetch()` helper. This function:

1. Prepends `http://localhost:3001` to the URL
2. Adds the JWT token from sessionStorage (if logged in)
3. Parses the JSON response
4. Throws an error with the server's message if the request fails

To add a new API call, create a function in the relevant service file (or create a new one in `services/`). See `services/github.js` for an example.

## How to Add a New Page

1. **Create the page component** in `src/pages/` (e.g., `ScannersPage.jsx`)
2. **Create a CSS file** alongside it (e.g., `ScannersPage.css`)
3. **Add the route** in `App.jsx`:
   ```jsx
   import ScannersPage from './pages/ScannersPage'
   // Inside <Routes>:
   <Route path="/scanners" element={isLoggedIn ? <ScannersPage /> : <Navigate to="/login" />} />
   ```
4. **Add a nav link** in `components/Navbar.jsx`
5. **Create a service file** in `services/` if the page needs its own API calls

## Authentication Flow

1. User submits credentials on the login page
2. Frontend calls `POST /api/auth/login`
3. Backend returns a JWT token and user object
4. Frontend stores both in `sessionStorage` (`tv_token` and `tv_user`)
5. All subsequent API calls include the token in the `Authorization` header
6. On logout, sessionStorage is cleared and the user is redirected to `/login`

**Note:** Session data is stored in `sessionStorage` (not `localStorage`), so it's cleared when the browser tab is closed.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Blank page or "network error" | Make sure the backend is running on port 3001 |
| "doctype is not valid JSON" | The backend returned an HTML error. Check that `.env` is configured in the backend. |
| Changes not showing up | Vite hot-reloads automatically, but try a hard refresh (`Ctrl+Shift+R`) if styles look stale |
| Port 5173 already in use | Vite will automatically try 5174. Or stop the other process on 5173. |
