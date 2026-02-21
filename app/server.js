const express = require("express");
const app = express();
app.use(express.json());

// Restrict CORS to specific trusted origin
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "https://yourdomain.com");
  next();
});

app.get("/", (req, res) => {
  res.send("mcp-sec-demo running");
});

// "search" endpoint
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.json({ query: q, results: [] });
});

// Safe alternative to eval() - only allow basic math expressions
app.post("/calc", (req, res) => {
  const expr = req.body?.expr || "1+1";
  // Safe: only allow numbers and basic math operators
  if (!/^[\d\s+\-*/().]+$/.test(expr)) {
    return res.status(400).json({ error: "Invalid expression. Only basic math allowed." });
  }
  const result = Function('"use strict"; return (' + expr + ')')();
  res.json({ expr, result });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));
