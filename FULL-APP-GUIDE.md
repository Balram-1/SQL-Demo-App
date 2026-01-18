# SQLi Demo Store — Complete Beginner’s Guide

This guide explains the entire SQLi Demo Store from the ground up. No prior knowledge is required. You’ll learn what the app does, how it works behind the scenes, the core technologies, where it’s intentionally insecure, and how to explore those issues safely.

> Important: This app is for learning only. Do not put it on the public internet.

## 1) What is this app?

It’s a small online shop you can run on your own computer. You can:
- View products and their pictures
- Add items to a shopping cart
- Create an account and log in
- Check out (fake payment form for demo)
- See your orders
- Use an Admin page to adjust stock or add/edit products

The twist: the app can run in two modes
- Vulnerable mode (insecure): It’s easy to attack using SQL Injection
- Secure mode: It uses safe database techniques to block those attacks

You can switch modes at any time using the “Toggle Mode” button in the header.

## 2) The big idea: what is SQL Injection (SQLi)?

- SQL is the language apps use to talk to databases (to save and load data).
- SQL Injection happens when user input is glued directly into SQL text.
- An attacker can change what the SQL means by adding special characters/words.

Example idea (don’t do this in real life):
- Login form asks for username and password
- Vulnerable app builds a query like: `... WHERE username = 'USER' AND password = 'PASS'`
- If an attacker puts username: `' OR '1'='1` and any password, the SQL can turn into something that always returns a user — bypassing login.

The secure way is to never glue raw input into SQL. Instead, use placeholders and pass values separately:
- Secure: `... WHERE username = ? AND password = ?` with ["USER", "PASS"] as values.

## 3) What technologies are used?

- Node.js: Lets JavaScript run on your computer as a server
- Express: A popular library for building web servers in Node
- SQLite: A simple, file-based database (no server needed)
- EJS: A template engine that creates HTML pages using data
- Sessions: Keep you logged in and remember your cart
- Nodemailer: Sends real emails (for signup verification)

Where things live in the project:
- `server.js`: All the routes and main server logic
- `src/db.js`: Database connection, tables, and starter data
- `views/*.ejs`: Page templates (what you see in the browser)
- `public/`: Static files like CSS and images

## 4) How does the app flow?

- Home (`/`): Shows featured products
- Products (`/products`): List and search products (can filter by category)
- Product page (`/product/:id`): Details for a single product
- Cart (`/cart`): Items you plan to buy
- Checkout (`/checkout`): A pretend payment form; creates an order
- Login/Signup (`/login`, `/signup`): Make an account and log in
- Orders (`/orders`): Look up an order (vulnerable in demo mode)
- Admin (`/admin`): For admin users only; adjust stock, create/edit products, see recent audits

What happens when you click around:
- Your browser requests a route (like `/products`)
- The server looks up info in the database (products, prices, etc.)
- It renders an EJS page (turns data into HTML)
- You see the page

## 5) What is stored in the database?

Tables:
- users: accounts (username, password, email, role, verified or not)
- products: items for sale (name, description, price, category, stock)
- orders: purchases (which user, total, status)
- order_items: which products were in each order
- payment_methods: stored payment details (intentionally insecure — for demo)
- audit_logs: who did what and when (login success/fail, stock changes, orders, product edits)

Note: In real life, passwords must be hashed (not stored as plain text), and payment details must not be stored like this. This app keeps them in plain text on purpose to keep the demo simple and highlight risks.

## 6) Vulnerable vs. Secure mode

- Vulnerable mode (default): Some routes build SQL by concatenating strings. That’s dangerous.
  - Examples: login, product search, product detail, order lookup
- Secure mode: Uses parameterized queries (placeholders like `?`) with separate values — the safe way.

Why keep both?: So you can see how attacks work and how they’re stopped when switching to secure mode.

## 7) Email verification (how it works)

- When you sign up, the app creates a 6-digit code and saves it for your account
- It tries to send that code to your email (using settings in the `.env` file)
- If email isn’t configured, the code is shown on the page so you can still verify during the demo
- You enter the code to verify your email, then you can log in

## 8) Admin features

- Only admin users can access `/admin`
- From there, you can:
  - Adjust stock (add/remove/set)
  - Create new products
  - Edit existing products
  - See a short list of recent audit log entries

Tip: Product images are chosen by the image “base name” (no file extension). The app will look for `.png`, `.jpg`, `.jpeg`, `.webp`, or `.gif` automatically. If no image is found, a placeholder is shown.

## 9) The audit log (why it matters)

- The app writes entries to `audit_logs` when important things happen
  - Login success or fail
  - Order created
  - Stock changed
  - Product created/updated
- Each entry records: who did it (if logged in), what action, which item, and when
- This helps investigate issues and understand what changed

## 10) How to run it

On Windows PowerShell:

1) Install Node.js from https://nodejs.org/
2) Install dependencies:
```powershell
npm install
```
3) (Optional) Configure email in `.env` (see README for details)
4) Start the app:
```powershell
npm start
```
5) Open in your browser:
- http://localhost:3000
- Or set a local name (hosts file) and use: http://sqli-demo-app.local:3000

To switch to secure mode:
```powershell
$env:VULN_MODE="off"; npm start
```

## 11) Try these safe learning exercises

- Login bypass (vulnerable mode): Try a username like `' OR '1'='1` and any password. Then switch to secure mode and try again.
- Search injection (vulnerable mode): Use a search like `%' OR '1'='1` and see how results change.
- Order ID tampering (vulnerable mode): On the orders page, try `1 OR 1=1` as the ID. Then switch to secure mode and retry.
- Stock/admin actions: See how the audit log records changes.

Remember: These are lessons to understand risks. Never attack systems you don’t own or have permission to test.

## 12) Glossary (plain language)

- Server: A program that answers web requests (our Node/Express app)
- Route: An address in the app like `/login` or `/products`
- Database: Where data is stored (SQLite file on your computer)
- SQL: Language used to talk to databases
- SQL Injection: Changing what SQL means by sneaking special input into it
- Parameterized Query: A safe SQL pattern that separates the query from the values
- Session: A temporary memory to remember who you are after you log in
- Template (EJS): A file that mixes HTML with small code to insert data
- Environment Variables: Settings (like `VULN_MODE`) controlled outside the code

## 13) What’s intentionally insecure (on purpose)?

- Passwords stored as plain text
- Payment information stored as plain text
- SQL queries built by string concatenation (in vulnerable mode)
- No rate limiting (can try many passwords quickly)
- No encryption (HTTP only, not HTTPS)

This is so you can see what goes wrong, then compare with the secure mode.

## 14) Where to go next

- Turn on secure mode and compare behavior
- Add password hashing (e.g., bcrypt)
- Stop storing payment info
- Add input validation and server-side checks everywhere
- Use real parameterized queries for all routes
- Add logging and monitoring for suspicious activity

---

You’re ready to explore! Open the app, try the exercises, and switch between modes to see the difference. If you’d like, I can also add a short video-like walkthrough script or a classroom worksheet version of this guide.
