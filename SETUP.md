# Study Log setup: Study Squad + Lock system (10 minutes, free, no card)

Study Squad and the Lock system (password gate + Admin Block) share one small online database. Do this once.

1. Go to console.firebase.google.com, sign in, tap **Add project**, name it (e.g. study-log), skip Analytics.
2. **Build > Realtime Database > Create Database.** Pick a location, choose **Locked mode**.
3. Open the **Rules** tab, delete everything, paste the contents of `database_rules.json`, tap **Publish**. (Already set up before? Paste again. The file now also covers the Lock system.)
4. **Build > Authentication > Get started > Sign-in method.** Enable **Anonymous** and also **Email/Password** (only the first switch, leave "Email link" off). Save.
5. **Authentication > Users > Add user.** Email: `admin@study-log.app`, Password: your Admin Block password (6+ characters). Do this right away, before sharing the app. This account is how Firebase checks the admin password, so the password is never stored in these files.
6. **Project settings (gear icon) > General > Your apps > Web (</>) > Register app.** Copy `apiKey`. Then open Realtime Database > Data and copy the URL at the top (starts with https://, ends with firebaseio.com or firebasedatabase.app).
7. Paste both into `firebase-config.js`. (The apiKey and URL are safe to keep in a public GitHub repo. The rules are what protect the data.)
8. Put ALL files in your GitHub repo and commit. New files: `lock.js`, `admin.js`. Changed files: `index.html`, `sw.js`, `database_rules.json`, `SETUP.md`. Open the app once online so it updates.

Then: drawer > **Study Squad** for squads, drawer > **Admin Block** for the lock tools.

## How the lock works
- A new install (also after delete + reinstall) sees a request form, then a password screen. **Already a user** skips the form and goes straight to the password screen. Everyone must enter the app password.
- The form (name, class, mobile, "Do you know AMARNATH", optional message, permission tick) cannot be changed once sent. It shows up in Admin Block with Call and Message buttons. **Request password** on the next screen adds a "Wants the password" tag. You send the password yourself.
- People who already had the app are let in once when they get this update, so nobody current is locked out. They only see the lock after a delete + reinstall.
- **Admin Block** (drawer, last item) asks for the admin password every time and locks itself again when closed or after 5 minutes away. Tabs: **Requests** (pending, mark done, call, message), **Users** (everyone who unlocked, search, delete), **Password** (change the app password or the admin password).
- Changing the app password affects new installs. Tick "Make everyone enter it again" to also lock people who are already inside (next time they are online).
- The default app password is stored only as a scrambled hash inside `lock.js`. The app password you set later is stored scrambled in the database. Neither can be read back.

## If you forget a password
- Admin password: Firebase > Authentication > Users > the admin account > reset or delete and add it again (step 5).
- App password: set a new one in Admin Block. If you cannot open Admin Block, Realtime Database > Data > delete the `lock/pw` node. The app password returns to the built-in default.

## Good to know
- Only you (the admin account) can read the form details and the user list. Other people cannot read them.
- This lock keeps casual sharing under control. Someone very technical could still bypass any lock that runs inside an app on their own phone. For hard enforcement you would need server-side hosting rules.
- Deleting the app or clearing app data creates a new device, so the lock shows again.
- Shared with squad members: name, emoji, minutes for today / week / all time, streak, and the subject name while you are studying live. Nothing else.
- Your Squad identity lives in the browser. Clearing app data creates a new identity (new code, out of the squad).
- A friend who is already in a squad must leave first, or ask the other person to enter their code.
- Requests and live status update while the app is open (about every 15 to 60 seconds). There are no push notifications.
