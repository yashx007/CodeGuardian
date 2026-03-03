/**
 * test_vuln_app.js — A deliberately vulnerable Express.js application
 * for testing CodeGuardian's detection and NIM LLM enrichment.
 */

const express = require("express");
const mysql = require("mysql");
const fs = require("fs");
const { exec, execSync } = require("child_process");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============================================================
// 1. Hardcoded secrets & credentials
// ============================================================
const DB_PASSWORD = "SuperSecret123!";
const API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx";
const JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const PRIVATE_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep...\n-----END RSA PRIVATE KEY-----";

// Hardcoded database connection
const db = mysql.createConnection({
    host: "production-db.internal.company.com",
    user: "admin",
    password: "Pr0duct!on_P@ssw0rd_2025",
    database: "users_prod",
});

// ============================================================
// 2. SQL injection vulnerabilities
// ============================================================
app.get("/users", (req, res) => {
    const username = req.query.username;
    // Direct string concatenation — classic SQL injection
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post("/login", (req, res) => {
    const { user, pass } = req.body;
    // Template literal SQL injection
    const sql = `SELECT * FROM accounts WHERE user='${user}' AND pass='${pass}'`;
    db.query(sql, (err, rows) => {
        if (err) return res.status(500).send("DB error");
        if (rows.length > 0) {
            const token = jwt.sign({ user }, JWT_SECRET);
            res.json({ token });
        } else {
            res.status(401).send("Invalid credentials");
        }
    });
});

app.get("/search", (req, res) => {
    const term = req.query.q;
    // Another SQL injection via concatenation
    const sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%' ORDER BY price";
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.delete("/user/:id", (req, res) => {
    // Unsanitized parameter in DELETE
    const sql = "DELETE FROM users WHERE id = " + req.params.id;
    db.query(sql, (err) => {
        if (err) return res.status(500).send("Error");
        res.send("Deleted");
    });
});

// ============================================================
// 3. Command injection
// ============================================================
app.get("/ping", (req, res) => {
    const host = req.query.host;
    // Direct command injection via exec
    exec("ping -c 4 " + host, (error, stdout, stderr) => {
        res.send(`<pre>${stdout}</pre><pre>${stderr}</pre>`);
    });
});

app.get("/lookup", (req, res) => {
    const domain = req.query.domain;
    // Template literal command injection
    const output = execSync(`nslookup ${domain}`);
    res.send(output.toString());
});

app.post("/deploy", (req, res) => {
    const branch = req.body.branch;
    // Command injection via string concat
    exec("git checkout " + branch + " && npm run build", (err, stdout) => {
        if (err) return res.status(500).send(err.message);
        res.send("Deployed: " + stdout);
    });
});

// ============================================================
// 4. XSS vulnerabilities
// ============================================================
app.get("/greet", (req, res) => {
    const name = req.query.name;
    // Reflected XSS — user input directly injected into HTML
    res.send("<h1>Welcome, " + name + "!</h1>");
});

app.get("/profile", (req, res) => {
    const bio = req.query.bio;
    // Template literal XSS
    res.send(`
        <html>
          <body>
            <div class="bio">${bio}</div>
            <script>
              document.getElementById('content').innerHTML = '${req.query.content}';
            </script>
          </body>
        </html>
    `);
});

// ============================================================
// 5. Insecure cryptography
// ============================================================
function hashPassword(password) {
    // MD5 is broken — should use bcrypt/argon2
    return crypto.createHash("md5").update(password).digest("hex");
}

function hashToken(token) {
    // SHA-1 is deprecated
    return crypto.createHash("sha1").update(token).digest("hex");
}

function encryptData(data, key) {
    // DES is insecure and deprecated
    const cipher = crypto.createCipheriv("des-ecb", key.slice(0, 8), "");
    return cipher.update(data, "utf8", "hex") + cipher.final("hex");
}

// ============================================================
// 6. eval / new Function — code injection
// ============================================================
app.post("/calculate", (req, res) => {
    const expression = req.body.expr;
    // eval with user input — remote code execution
    const result = eval(expression);
    res.json({ result });
});

app.post("/transform", (req, res) => {
    const code = req.body.code;
    // new Function with user input — also code execution
    const fn = new Function("data", code);
    const output = fn(req.body.data);
    res.json({ output });
});

app.get("/template", (req, res) => {
    const tpl = req.query.tpl;
    // eval to render templates — dangerous
    const rendered = eval("`" + tpl + "`");
    res.send(rendered);
});

// ============================================================
// 7. Path traversal / arbitrary file read
// ============================================================
app.get("/file", (req, res) => {
    const filename = req.query.name;
    // No sanitization — path traversal possible (../../etc/passwd)
    const content = fs.readFileSync("/var/data/" + filename, "utf-8");
    res.send(content);
});

app.get("/download", (req, res) => {
    const filepath = req.query.path;
    // Directly using user-supplied path
    res.sendFile(filepath);
});

app.get("/logs", (req, res) => {
    const logFile = req.query.file;
    // Template literal path traversal
    const data = fs.readFileSync(`/var/log/${logFile}`, "utf8");
    res.type("text/plain").send(data);
});

// ============================================================
// 8. Insecure deserialization
// ============================================================
app.post("/import", (req, res) => {
    const serialized = req.body.payload;
    // Deserializing untrusted JSON that gets passed to eval
    const obj = eval("(" + serialized + ")");
    res.json({ imported: obj });
});

// ============================================================
// 9. Insecure random number generation
// ============================================================
function generateSessionId() {
    // Math.random is NOT cryptographically secure
    return Math.random().toString(36).substring(2);
}

function generateResetToken() {
    // Predictable tokens based on timestamp
    return "reset-" + Date.now().toString(36);
}

// ============================================================
// 10. Missing security headers / CORS misconfiguration
// ============================================================
app.use((req, res, next) => {
    // Wildcard CORS — allows any origin
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE");
    res.setHeader("Access-Control-Allow-Headers", "*");
    next();
});

// ============================================================
// 11. Information disclosure
// ============================================================
app.use((err, req, res, next) => {
    // Leaking full stack traces to the client
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        env: process.env,
    });
});

app.get("/debug", (req, res) => {
    // Exposing environment variables including secrets
    res.json({
        env: process.env,
        config: {
            dbPassword: DB_PASSWORD,
            apiKey: API_KEY,
            awsKey: AWS_ACCESS_KEY,
        },
    });
});

// ============================================================
// 12. Prototype pollution
// ============================================================
app.post("/config", (req, res) => {
    const updates = req.body;
    const config = {};
    // Merging user input without sanitization — prototype pollution
    for (const key in updates) {
        config[key] = updates[key];
    }
    res.json(config);
});

function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// ============================================================
// 13. Unvalidated redirects
// ============================================================
app.get("/redirect", (req, res) => {
    const url = req.query.url;
    // Open redirect — attacker can redirect to phishing site
    res.redirect(url);
});

app.get("/goto", (req, res) => {
    const next = req.query.next;
    // Another open redirect
    res.redirect(302, next);
});

// ============================================================
// 14. Server startup with debug/verbose mode
// ============================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log("DB Password:", DB_PASSWORD);
    console.log("API Key:", API_KEY);
    console.log("AWS Key:", AWS_ACCESS_KEY);
});
