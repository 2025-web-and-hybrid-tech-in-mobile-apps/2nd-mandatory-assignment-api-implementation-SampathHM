const express = require("express");
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

let users = [];
let authorizedTokens = [];
let highScores = [];

// Helper functions
const validateCredentials = (userHandle, password) => {
  return typeof userHandle === "string" && 
         typeof password === "string" &&
         userHandle.length >= 6 && 
         password.length >= 6;
};

const generateToken = (userHandle) => `${userHandle}${Date.now()}`;

// Middleware
const validateSignupLoginBody = (req, res, next) => {
  const { userHandle, password } = req.body;
  if (!validateCredentials(userHandle, password)) {
    return res.status(400).send("Bad Request: Missing or invalid fields");
  }
  next();
};

const checkExtraFields = (allowedFields) => (req, res, next) => {
  const extraFields = Object.keys(req.body).filter(k => !allowedFields.includes(k));
  if (extraFields.length > 0) {
    return res.status(400).send("Bad Request: Extra fields detected");
  }
  next();
};

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token || !authorizedTokens.includes(token)) {
    return res.status(401).send("Unauthorized, JWT token is missing or invalid");
  }
  next();
};

// Routes
app.post("/signup", 
  validateSignupLoginBody,
  checkExtraFields(["userHandle", "password"]),
  (req, res) => {
    const { userHandle, password } = req.body;
    
    if (users.some(user => user.userHandle === userHandle)) {
      return res.status(400).send("User is already exists");
    }

    users.push({ userHandle, password });
    res.status(201).send("User registered successfully");
  }
);

app.post("/login",
  validateSignupLoginBody,
  checkExtraFields(["userHandle", "password"]),
  (req, res) => {
    const { userHandle, password } = req.body;
    const user = users.find(u => u.userHandle === userHandle && u.password === password);

    if (!user) {
      return res.status(401).send("Unauthorized: Incorrect username or password");
    }

    const token = generateToken(userHandle);
    authorizedTokens.push(token);
    res.status(200).json({ jsonWebToken: token });
  }
);

app.post("/high-scores",
  authenticateToken,
  (req, res) => {
    const requiredFields = ["level", "userHandle", "score", "timestamp"];
    if (requiredFields.some(field => !req.body[field])) {
      return res.status(400).send("Invalid request body");
    }

    highScores.push(req.body);
    res.status(201).send("High score posted successfully");
  }
);

app.get("/high-scores", (req, res) => {
  const level = req.query.level;
  const page = req.query.page || 1;
  
  if (!level) {
    return res.status(400).send("Level is required");
  }

  const filtered = highScores
    .filter(hs => hs.level === level)
    .sort((a, b) => b.score - a.score);

  const paginated = filtered.slice((page - 1) * 20, page * 20);
  res.status(200).json(paginated);
});


// Start and close server
let serverInstance = null;
module.exports = {
  start: () => {
    serverInstance = app.listen(port, () => 
      console.log(`Server running on port ${port}`));
  },
  close: () => {
    serverInstance.close(() => {
      users = [];
      authorizedTokens = [];
      highScores = [];
    });
  }
};