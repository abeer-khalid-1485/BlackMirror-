const express = require("express");
const bodyParser = require("body-parser");
const fetch = require("node-fetch");
const path = require("path");
const Database = require("better-sqlite3");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();
const port = 3000;

const clientPath = path.join(__dirname, "../client");
const assetsPath = path.join(__dirname, "../assets");

app.use(express.static(clientPath));
app.use("/assets", express.static(assetsPath));
app.use(bodyParser.json());

// قاعدة البيانات
const dbPath = path.join(__dirname, "report_log.db");
const db = new Database(dbPath);

db.prepare(`
  CREATE TABLE IF NOT EXISTS phishing_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// الصفحة الرئيسية
app.get("/", (req, res) => {
  res.sendFile(path.join(clientPath, "login.html"));
});

// فحص الرابط باستخدام Google Safe Browsing API
app.post("/check-url", async (req, res) => {
  const url = req.body.url;
  if (!url) {
    return res.status(400).json({ error: "لم يتم توفير رابط" });
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        client: {
          clientId: "blackmirror-project",
          clientVersion: "1.0.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      })
    });

    const data = await response.json();

    if (data && data.matches) {
      res.json({ safe: false, info: "🚫 الرابط مشبوه حسب Google Safe Browsing" });
    } else {
      res.json({ safe: true, info: "✅ الرابط آمن حسب Google" });
    }
  } catch (err) {
    console.error("API error:", err.message);
    res.status(500).json({ error: "فشل الاتصال بـ Google API" });
  }
});

// بلاغ عن رابط تصيد
app.post("/report-url", (req, res) => {
  const url = req.body.url;
  if (!url) {
    return res.status(400).json({ error: "الرابط مفقود" });
  }

  try {
    db.prepare("INSERT INTO phishing_reports (url) VALUES (?)").run(url);
    res.json({ success: true, message: "✅ تم الإبلاغ عن الرابط بنجاح" });
  } catch (err) {
    console.error("DB error:", err.message);
    res.status(500).json({ error: "❌ مشكلة في قاعدة البيانات" });
  }
});

// بدء التشغيل
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
