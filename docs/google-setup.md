# Google setup

Postroom connects Gmail, Google Calendar, Google Tasks and Google Contacts with an OAuth
client that you create in your own Google Cloud project. Your tokens are issued to your
client and stored only on your server. You do this once; afterwards you can connect any
number of Google accounts from the admin UI.

Only want Gmail's mail? You can skip this guide and add the mailbox as an IMAP account
with a Google app password instead (see [Provider settings](providers.md#mail)). Google
calendars, tasks and contacts need the OAuth client described here.

You need:

- Postroom running at its public address, for example `https://mcp.example.com`
  (see the [quick start](../README.md#quick-start));
- a Google account to own the Cloud project (it can be the one you connect, or another).

Google renames the console's menus from time to time. The steps below use the names from
the current console ("Google Auth Platform"); older consoles have the same settings under
**APIs & Services → OAuth consent screen**.

## 1. Create a project

1. Open the [Google Cloud console](https://console.cloud.google.com/).
2. Use the project picker at the top and choose **New project**. Name it, for example,
   "Postroom". No billing account is needed.
3. Make sure the new project is selected for the next steps.

## 2. Enable the APIs

Open **APIs & Services → Library**, search for each of these APIs and click **Enable**:

| API | Used for |
|---|---|
| Google Calendar API | `list_calendars`, `list_events` and the event tools |
| Google Tasks API | `list_task_lists`, `list_tasks` and the task tools |
| People API | `search_contacts` |

The **Gmail API is not needed.** Postroom reads Gmail over IMAP and sends over SMTP, both
signed in with an OAuth token (XOAUTH2) that carries the `https://mail.google.com/` scope.

## 3. Configure the consent screen

Open **Google Auth Platform** (or **APIs & Services → OAuth consent screen**) and click
**Get started** if the project has no consent screen yet.

1. **App information:** an app name (for example "Postroom") and your email as the user
   support email.
2. **Audience:**
   - **External** for personal Gmail accounts, or when you connect accounts from more than
     one organization.
   - **Internal** if every account you will connect belongs to your own Google Workspace
     organization. Internal apps are not subject to the testing and verification rules
     below.
3. **Contact information:** your email. Accept the user data policy and create the screen.
4. **Data access** (or "Scopes"): click **Add or remove scopes** and add the scopes
   Postroom requests. Paste them into **Manually add scopes** if they are not in the list:

   | Scope | Why |
   |---|---|
   | `openid`, `email` | Identify which Google account was connected. |
   | `https://mail.google.com/` | Gmail over IMAP and SMTP (read, organise, drafts, send). |
   | `https://www.googleapis.com/auth/calendar.events` | Create, change and delete events. |
   | `https://www.googleapis.com/auth/calendar.readonly` | List calendars and events. |
   | `https://www.googleapis.com/auth/tasks` | Read and change tasks. |
   | `https://www.googleapis.com/auth/contacts.readonly` | Search your contacts. |
   | `https://www.googleapis.com/auth/contacts.other.readonly` | Search "other contacts" (people you have emailed). |

   Postroom always asks for this whole set. Google lists `https://mail.google.com/` as a
   restricted scope; that matters for apps that other people use, not for yours (see step 5).
5. **Audience → Test users** (External only): add the Google account(s) you will connect.

## 4. Publish the app (External only)

This step decides whether you have to reconnect every week.

- While an External app's publishing status is **Testing**, Google expires its refresh
  tokens after **7 days**. Postroom would then mark the account "Login failed" and you would
  have to click **Reconnect** each week.
- Open **Audience** and click **Publish app** to switch it to **In production**. Refresh
  tokens then stay valid until you revoke them, change your Google password (for Gmail
  scopes) or leave them unused for six months.

You do **not** need to submit the app for Google's verification. An unverified app in
production works for its own developer and a small number of users (Google caps unverified
apps at 100 users), which is irrelevant when you are the only user. The only difference is
a warning when you connect: Google shows **"Google hasn't verified this app"**. Click
**Advanced**, then **Go to Postroom (unsafe)**. It is your own app talking to your own
server.

Google may show the publishing dialog's notes about verification; you can ignore them for
personal use.

## 5. Create the OAuth client

1. Open **Clients** (or **APIs & Services → Credentials → Create credentials → OAuth
   client ID**).
2. **Application type:** **Web application**. Name it, for example, "Postroom".
3. **Authorized redirect URIs:** add exactly

   ```
   https://mcp.example.com/admin/google/callback
   ```

   with your own domain: it is your `POSTROOM_PUBLIC_URL` followed by
   `/admin/google/callback`. **Authorized JavaScript origins** can stay empty.
4. Click **Create** and copy the **Client ID** and the **Client secret**. (Newer consoles
   show the secret only once; download the JSON if you want a copy.)

## 6. Configure Postroom

Add both values to `.env`:

```sh
POSTROOM_GOOGLE_CLIENT_ID=123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com
POSTROOM_GOOGLE_CLIENT_SECRET=GOCSPX-...
```

and restart:

```sh
docker compose up -d
```

The admin dashboard now shows a **Connect Google account** button. It appears only when
both settings are set.

## 7. Connect an account

1. In the admin, click **Connect Google account**.
2. Choose the Google account, click through the unverified-app warning if it appears, and
   allow access. Keep **every box ticked**, Gmail in particular: without the Gmail scope
   Postroom refuses the connection and asks you to try again.
3. You are sent back to the admin, where the account appears and is checked at once.

Google accounts need no IMAP, SMTP, CalDAV or CardDAV settings. Use **Edit** to change
their display name or [access level](../README.md#access-levels), and **Reconnect** if
Google ever revokes the access.

## Google Workspace

If the account belongs to a Google Workspace organization, its administrator can block
third-party apps:

- **App access control:** in the Admin console open **Security → Access and data control →
  API controls → Manage third-party app access**, add the app by its OAuth client ID and
  set it to **Trusted**. Without this, Google may answer "This app is blocked" or
  "Access blocked: your organization's policy".
- **IMAP:** Gmail over IMAP must be allowed for the users
  (**Apps → Google Workspace → Gmail → End user access → POP and IMAP access**).

With an **Internal** consent screen (step 3), the app is trusted inside your own
organization and the 7-day testing limit does not apply.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Error 400: redirect_uri_mismatch` | The redirect URI in the OAuth client does not match `POSTROOM_PUBLIC_URL` + `/admin/google/callback` exactly (scheme, host, no trailing slash). |
| `Error 403: access_denied` while in Testing | The Google account is not on the test user list, or publish the app. |
| "Google did not return a refresh token" | Google had already granted access earlier. Remove Postroom under your Google account's **Security → Your connections to third-party apps & services**, then connect again. |
| "Gmail access was not granted" | The Gmail box was unticked on Google's consent screen. Connect again and allow it. |
| The account shows "Login failed" after about a week | The app is still in Testing. Publish it (step 4) and click **Reconnect**. |
| No **Connect Google account** button | `POSTROOM_GOOGLE_CLIENT_ID` or `POSTROOM_GOOGLE_CLIENT_SECRET` is empty, or the container was not restarted. |
