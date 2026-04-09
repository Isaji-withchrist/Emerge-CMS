# EMERGE CMS — Setup & Running Guide

## What this is
A full-stack Content Management System with:
- **Flask** backend (Python, built-in — no npm needed)
- **SQLite** database (file-based, zero configuration)
- **JWT** authentication
- **Role-based access control** with invite-code verification
- Real file uploads stored on disk

---

## Requirements
- Python 3.8 or higher
- Flask (`pip install flask`)

That's it. SQLite is built into Python.

---

## How to run

```bash
# 1. Navigate to this folder
cd emerge-backend

# 2. Start the server
python3 server.py

# 3. Open your browser
# http://localhost:5000
```

The server will:
- Create `emerge.db` (the database) automatically on first run
- Create an `uploads/` folder for media files
- Serve the frontend from `public/index.html`

---

## First-time setup

1. Open `http://localhost:5000`
2. Click **Get started**
3. Register with the **Administrator** role
4. Complete the 4-step setup wizard (site name, workflow, first category)
5. You're in — dashboard is clean and empty, ready to use

---

## Role System

| Role | What they can do |
|------|-----------------|
| **Administrator** | Everything — users, settings, invite codes, publish, delete |
| **Editor** | Approve/reject posts, moderate comments, manage categories |
| **Author** | Write and submit their own posts for review |
| **Visitor** | Read-only (future use) |

---

## How invite codes work

Registering as **Author** is open to anyone (or can be locked down).

Registering as **Editor** or **Administrator** requires an **invite code**.

**To generate an invite code:**
1. Sign in as an Administrator
2. Go to **Settings → Invite Codes**
3. Click **Generate Editor Invite** or **Generate Admin Invite**
4. Copy the code (format: `XXXX-XXXX-XXXX`)
5. Share it with the person you want to invite
6. They enter it on the Register page when selecting Editor or Admin role

Each code can only be used **once** and is tied to a specific role.

---

## Multi-device / multi-browser

Because this is a real server with a real database:
- Sign in on your phone → changes appear on your laptop instantly
- Your classmate registers → you see them in Users immediately
- One author submits → every editor sees the pending badge

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Port the server listens on |
| `EMERGE_SECRET` | auto-generated | JWT signing secret — set this to a fixed value in production |

```bash
# Example with custom port and fixed secret
EMERGE_SECRET="my-fixed-secret-key" PORT=8080 python3 server.py
```

---

## File structure

```
emerge-backend/
├── server.py          ← The entire backend
├── emerge.db          ← SQLite database (created on first run)
├── uploads/           ← Uploaded media files
├── public/
│   └── index.html     ← The entire frontend
└── README.md          ← This file
```

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/setup/status` | None | Check if setup is done |
| POST | `/api/setup/complete` | Admin | Complete setup wizard |
| POST | `/api/auth/register` | None | Create account |
| POST | `/api/auth/login` | None | Sign in |
| GET | `/api/auth/me` | Any | Get current user |
| GET | `/api/invites` | Admin | List all invite codes |
| POST | `/api/invites` | Admin | Create invite code |
| DELETE | `/api/invites/:id` | Admin | Delete unused code |
| POST | `/api/invites/validate` | None | Check if code is valid |
| GET | `/api/posts` | Any | List posts |
| POST | `/api/posts` | Any | Create post |
| PUT | `/api/posts/:id` | Author/Editor/Admin | Update post |
| DELETE | `/api/posts/:id` | Author/Editor/Admin | Delete post |
| GET | `/api/categories` | None | List categories |
| POST/PUT/DELETE | `/api/categories` | Editor/Admin | Manage categories |
| GET | `/api/users` | Editor/Admin | List users |
| POST | `/api/users` | Admin | Create user directly |
| PUT | `/api/users/:id` | Self/Admin | Update user |
| PATCH | `/api/users/:id/status` | Admin | Suspend/reactivate |
| GET | `/api/comments` | Editor/Admin | List all comments |
| PATCH | `/api/comments/:id/moderate` | Editor/Admin | Approve/reject |
| GET | `/api/media` | Any | List media |
| POST | `/api/media` | Any | Upload file |
| DELETE | `/api/media/:id` | Owner/Editor/Admin | Delete file |
| GET | `/api/analytics` | Any | Analytics data |
| GET | `/api/notifications` | Any | User notifications |
| GET | `/api/settings` | Any | Get settings |
| PUT | `/api/settings` | Admin | Update settings |