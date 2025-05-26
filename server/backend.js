const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const Database = require("better-sqlite3");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const port = process.env.PORT || 3000;

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

db.prepare(`
  CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT,
    result TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// الصفحة الرئيسية
app.get("/", (req, res) => {
  res.sendFile(path.join(clientPath, "login.html"));
});

// فحص الرابط
app.post("/check-url", async (req, res) => {
  const url = req.body.url;
  if (!url) return res.status(400).json({ error: "الرابط مفقود" });

  try {
    // محاكي بسيط للفحص بدل Google API
    let resultText = url.includes("https") ? "آمن" : "مشبوه";
    const safe = resultText === "آمن";

    db.prepare("INSERT INTO scan_logs (url, result) VALUES (?, ?)").run(url, resultText);

    res.json({
      safe,
      info: safe ? "✅ الرابط آمن" : "🚫 الرابط مشبوه"
    });
  } catch (err) {
    console.error("API error:", err.message);
    res.status(500).json({ error: "⚠️ حدث خطأ في الفحص" });
  }
});

// بلاغ عن رابط
app.post("/report-url", (req, res) => {
  const url = req.body.url;
  if (!url) return res.status(400).json({ error: "الرابط مفقود" });

  try {
    db.prepare("INSERT INTO phishing_reports (url) VALUES (?)").run(url);
    res.json({ success: true, message: "✅ تم الإبلاغ، شكرًا لمساهمتك." });
  } catch (err) {
    console.error("DB error:", err.message);
    res.status(500).json({ error: "❌ خطأ في قاعدة البيانات" });
  }
});

// الإحصائيات
app.get("/stats", (req, res) => {
  try {
    const totalScans = db.prepare("SELECT COUNT(*) AS count FROM scan_logs").get().count;
    const totalReports = db.prepare("SELECT COUNT(*) AS count FROM phishing_reports").get().count;

    res.json({ totalScans, totalReports });
  } catch (err) {
    console.error("Stats error:", err.message);
    res.status(500).json({ error: "❌ خطأ في الإحصائيات" });
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
