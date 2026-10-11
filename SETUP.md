# Study Log: Lock + Admin Block (setup guide)

Free, no card. Do the setup once (about 10 minutes). Nothing in your old features was changed.

## What is new

- **Lock for every new install.** A new install (also after delete + reinstall) must send a small form, then enter a **one-time password** that only you can give.
- **Admin Block** (drawer, last item). It always asks for your admin password. Inside it has four tabs:
  - **Requests**: who is asking, with Call / Message buttons and a ready one-time password to copy.
  - **Users**: everyone who opened the app. For each person: **Inspect**, **Popup**, **Block / Unblock**, **Ask details**.
  - **Popups**: send a popup to everyone or to one person, and see who has seen it.
  - **Password**: change your admin password.
- **Block** a person for 1 hour, 6 hours, 1 day, 7 days, or until you unblock. You can add a message, and you can give a **one-time unblock password** so the person can open the app again when they type it.
- **Inspect** shows what a person is doing in the app: live timer, today / 7 days / all time, streak, goal, subjects, recent sessions, to-do list, achievements.
- **Popups** have different looks: Info (blue), Warning (yellow), Good (green), Alert (red), Privacy, Block, Update, Password. A **password popup** cannot be closed until the password you set for it is typed.
- **Update popup**: when you upload new files to GitHub, everyone sees "Update available" and cannot use the app until they tap **Update**.

## Setup (once)

1. Go to console.firebase.google.com and open your project (`study-tracker-9b5c9`). If you do not have one: **Add project**, name it, skip Analytics.
2. **Build > Realtime Database > Create Database** (if not made yet). Pick any location. Choose **Locked mode**.
3. **Realtime Database > Rules** tab. Delete everything. Paste the whole text of `database_rules.json` (open it, select all, copy; it was also sent to you as `firebase-rules-copy-paste.txt`, same text). Tap **Publish**. **Do this again even if you did it before: the rules are new in this version.**
4. **Build > Authentication > Get started > Sign-in method.** Switch **Anonymous** ON and also **Email/Password** ON (only the first switch, leave "Email link" off). Save.
5. **Authentication > Users > Add user.** Email: `admin@study-log.app`. Password: **your own admin password** (6 or more characters, choose it yourself and remember it). This is how Firebase checks your admin password. The password is not written in any file.
6. Your `apiKey` and database URL are already filled into `firebase-config.js`. You do not need to change it.
7. **Upload ALL files** from this folder to your GitHub repo (GitHub > your repo > **Add file > Upload files** > drag everything > **Commit changes**). New files: `lock.js`, `admin.js`. Changed files: `index.html`, `sw.js`, `database_rules.json`, `SETUP.md`. The other files stay the same.
8. Wait 1 or 2 minutes, then open the app once while online. Accept the privacy notice. Open the drawer, tap **Admin Block**, and enter your admin password.

Study Squad needs the same Firebase setup. If it showed "One-time setup needed", steps 3 to 5 fix it.

## How people get in

- A new install sees a form: name, class, mobile, "Do you know AMARNATH?" (Yes / No), an optional message to admin, and a tick to allow calls / messages. **Send** stays off until everything is filled. Details cannot be changed after sending.
- The next page has a password box and a **Request password** button. Pressing it tells you they are waiting. They can ask again after 30 minutes.
- **Already a user** (on the form page) skips the form. On the password page that person can still press **Request password**. You will see them as "Unregistered device" with a short **device ID**; the person can tell you the same ID so you know who it is.
- Open **Admin Block > Requests**. A one-time password is made for each request. Tap **Copy** (or **Message**, which fills the text for you) and send it to that person. It works **once**, on **that phone only**. **New** makes a fresh one (the old one stops working). **Mark done** moves the request out of the list.
- There is no shared default password. Your admin password also opens any fresh install, for your own use.
- People who already had the app are let in once when they get this update, so nobody is locked out suddenly.

## Admin Block guide

- **Existing users show as "Unregistered device".** Tap **Ask details** on one person, or **Ask all** at the top of the Users tab. They see the form next time the app is open and cannot use the app until they send it. Then you see name, class and mobile.
- **Block.** Users > Block. Choose how long, write a message (optional), and tick "Let them unblock themselves with a one-time password" if you want. Send that password yourself. When they type it, the block lifts on their phone. **Unblock** lifts it from your side.
- **Inspect.** Users > Inspect. Tap **Refresh** or **Watch live** to see fresh numbers. The phone answers while the app is open. Each person sees the privacy notice first, which tells them you can see their study activity.
- **Popup.** Users > Popup (one person), or Popups > New popup (everyone or one person). Choose **Message** (with a look) or **Password popup** (stays until the password is typed; you set the password). The preview shows how it will look.
- **Delete** (the bin on a person's card) removes their request, password and saved data from your list. It does **not** block them, and they appear again when they open the app. Use Block to stop someone.
- Admin Block locks itself again when you close it or after 5 minutes away.

## Updating the app later

Upload the new files to GitHub as before. Within a few minutes of opening the app, everyone sees the **Update** popup. GitHub can take up to about 10 minutes to start serving new files.

## If you forget the admin password

Firebase > Authentication > Users > `admin@study-log.app` > **Delete account**. Then **Add user** again (step 5) with a new password. (Do not use "Reset password": `admin@study-log.app` is not a real mailbox.)

## If you see a message

- "The database refused this" means the rules are not published yet (step 3) or the admin user is missing (step 5).
- "Email/Password sign-in is switched off" means step 4 is not done.
- "The apiKey in firebase-config.js is not valid" means the apiKey was changed or is wrong.
- "Session expired. Enter the password again." Just type the admin password again.

## Good to know

- Only your admin account can read the form details, the user list and the one-time passwords. Other people cannot.
- Passwords are saved scrambled (salted PBKDF2). Your one-time passwords are also kept as readable text in an admin-only place, so you can copy them later.
- Changes (block, popup, ask details) reach a phone within about a minute while the app is open, or right when it is next opened. There are no push notifications.
- Inspect shows the app's data, not a live copy of the screen.
- Any lock inside an app on someone's phone can be bypassed by a very technical person. This keeps normal use under control. Hard enforcement would need a server.
- Deleting the app or clearing app data makes a new device, so the lock shows again.
- Shared with Study Squad members: name, emoji, minutes for today / week / all time, streak, and the subject while you study live. Nothing else.
