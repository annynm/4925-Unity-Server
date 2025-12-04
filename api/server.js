import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import { query, initDb } from "../database/db.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();

const allowedOrigins = [
  /^http:\/\/localhost:\d+$/,
  /^http:\/\/127\.0\.0\.1:\d+$/,
  "https://yourgame.com",
  "https://www.yourgamesite.com",
  "https://*.itch.io",
  "https://*.unity3dusercontent.com",
  "http://localhost:8080",
  "http://localhost:3000",
  "null",
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (!origin) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    res.header("Access-Control-Expose-Headers", "Content-Length, X-Request-Id");
    res.header("Access-Control-Max-Age", "86400");
    return next();
  }
  
  let isAllowed = false;
  
  for (const allowedOrigin of allowedOrigins) {
    if (typeof allowedOrigin === 'string') {
      if (allowedOrigin === origin) {
        isAllowed = true;
        break;
      }
    } else if (allowedOrigin instanceof RegExp) {
      if (allowedOrigin.test(origin)) {
        isAllowed = true;
        break;
      }
    }
  }
  
  if (isAllowed) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    res.header("Access-Control-Expose-Headers", "Content-Length, X-Request-Id");
    res.header("Access-Control-Max-Age", "86400");
    res.header("Access-Control-Allow-Credentials", "false");
  } else {
    console.log(`Blocked by CORS: ${origin}`);
    return res.status(403).json({ error: "Not allowed by CORS" });
  }
  
  next();
});

app.options("*", (req, res) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.header("Access-Control-Max-Age", "86400");
  res.header("Access-Control-Allow-Credentials", "false");
  res.sendStatus(200);
});

app.use((req, res, next) => {
  res.header("X-Content-Type-Options", "nosniff");
  res.header("X-Frame-Options", "DENY");
  res.header("X-XSS-Protection", "1; mode=block");
  next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let dbInitialized = false;

app.use(async (req, res, next) => {
  if (!dbInitialized) {
    await initDb();
    dbInitialized = true;
  }
  next();
});

app.get("/", (req, res) => {
  res.json({ 
    status: "API is running",
    version: "1.0.0"
  });
});

app.get("/unity-test", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString()
  });
});

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const existingUser = await query(
      "SELECT * FROM users WHERE username = $1",
      [username],
    );
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Username already exists" });
    }

    const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING userid, username",
      [username, hashedPassword],
    );

    res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const result = await query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    res.json({
      message: "Login successful",
      user: {
        userid: user.userid,
        username: user.username,
      },
      token: null,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const result = await query("SELECT userid, username FROM users");
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    database: "Connected"
  });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

export default app;
