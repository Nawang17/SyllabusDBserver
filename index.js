require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const API_KEY = process.env.VIRUSTOTAL_API_KEY;

const {
  Client,
  Events,
  ActivityType,
  GatewayIntentBits,
} = require("discord.js");

const app = express();
app.use(cors());
app.use(express.json());

const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(",") || [];

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages],
});

const FormData = require("form-data");
const Mailgun = require("mailgun.js");

const mailgun = new Mailgun(FormData);
const mg = mailgun.client({
  username: "api",
  key: process.env.MAILGUN_API_KEY,
});
const MAILGUN_DOMAIN = process.env.MAILGUN_DOMAIN;

// ---- Discord bot ----
client.once(Events.ClientReady, (c) => {
  console.log(`Discord bot ready! Logged in as ${c.user.tag}`);
  c.user.setPresence({
    activities: [{ name: "syllabusdb.com", type: ActivityType.Watching }],
  });
});
client.login(process.env.DISCORD_BOT_TOKEN);

// ---- CORS (restrict to allowed origins) ----
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"], // allow POST for notify endpoints
  })
);

// ---- Routes ----
app.get("/", async (req, res) => {
  res.send(
    "Welcome to the SyllabusDB API. Visit https://syllabusdb.com for more information."
  );
});

app.get("/scan", async (req, res) => {
  if (req.headers["x-admin-token"] !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const fileUrl = req.query.url;
  if (!fileUrl) return res.status(400).json({ error: "fileUrl is required" });

  try {
    console.log(`Scanning URL`);
    // Step 1: Submit URL
    const scanRes = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url: fileUrl }),
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const scanId = scanRes.data.data.id;

    // Step 2: Poll for result
    let result,
      status = "queued";
    while (status === "queued") {
      await new Promise((resolve) => setTimeout(resolve, 10000));
      const analysis = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${scanId}`,
        { headers: { "x-apikey": API_KEY } }
      );
      status = analysis.data.data.attributes.status;
      result = analysis.data;
    }

    console.log(`Scan completed`);
    res.json(result.data.attributes.stats);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "Scan failed" });
  }
});

// POST /notify-upload
app.post("/notify-upload", async (req, res) => {
  const { collegeName, courseCode } = req.body;

  if (!collegeName || !courseCode) {
    return res.status(400).json({ error: "Missing collegeName or courseCode" });
  }

  try {
    // Send Discord notification to admin
    try {
      await client?.users?.send(
        process.env.USERID,
        `**📄 New Syllabus Upload!**\n**${collegeName}** (${courseCode})`
      );
    } catch (err) {
      console.error("❌ Discord notification failed:", err);
    }

    console.log("✅ Notification sent successfully");
    res.json({ message: "Notification sent" });
  } catch (err) {
    console.error("❌ Discord Notification send failed:", err);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

app.post("/notify-college-request", async (req, res) => {
  const { collegeName, location } = req.body;

  if (!collegeName || !location) {
    return res.status(400).json({ error: "Missing collegeName or location" });
  }

  try {
    // Send Discord notification to admin
    try {
      await client?.users?.send(
        process.env.USERID,
        `**🎓 New College Request!**\n**${collegeName}** (${location})`
      );
    } catch (err) {
      console.error("❌ Discord notification failed:", err);
    }

    console.log("✅ Notification sent successfully");
    res.json({ message: "Notification sent" });
  } catch (err) {
    console.error("❌ Discord Notification send failed:", err);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

app.post("/notify-user", async (req, res) => {
  const { email, subject, message } = req.body;

  if (!email || !subject || !message) {
    return res
      .status(400)
      .json({ error: "Missing email, subject, or message" });
  }

  // Standard footer for all emails
  const footer = `
---
This is an automated email, please do not reply.
Need help? Contact katophh@gmail.com
Unsubscribe: https://syllabusdb.com/settings
Visit us: https://syllabusdb.com

`;

  try {
    await mg.messages.create(MAILGUN_DOMAIN, {
      from: `SyllabusDB Notifications <no-reply@${MAILGUN_DOMAIN}>`,
      to: [email],
      subject,
      text: `${message}\n\n${footer}`,
    });

    console.log(`✅ Mailgun email sent to ${email}`);
    res.json({ message: "Email sent" });
  } catch (err) {
    console.error("❌ Mailgun email failed:", err?.response?.body || err);
    res.status(500).json({ error: "Failed to send email" });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
