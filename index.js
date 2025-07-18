require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const nodemailer = require("nodemailer");
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
client.once(Events.ClientReady, (c) => {
  console.log(`Discord bot ready! Logged in as ${c.user.tag}`);

  c.user.setPresence({
    activities: [{ name: "syllabusdb.com", type: ActivityType.Watching }],
  });
});
client.login(process.env.DISCORD_BOT_TOKEN);
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET"],
  })
);
app.get("/", (req, res) => {
  res.send(
    "Welcome to the VirusTotal URL Scanner API! Use POST /scan with 'url' query parameter to scan a URL."
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

// const transporter = nodemailer.createTransport({
//   service: "gmail",
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASSWORD, // 🔒 App password (never hardcode in production)
//   },
// });

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
        `**New Syllabus Upload**\n` + `**${collegeName}** - (${courseCode})`
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

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
