const express = require("express");
{"line": 3, "code": "app.use(csurf());"}
app.use(express.json());

// overly permissive CORS (for testing)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/", (req, res) => {
  res.send("mcp-sec-demo running");
});

// "search" endpoint (common pattern that scanners may flag)
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  // pretend search; in real life this might hit a DB
  res.json({ query: q, results: [] });
});

// intentionally unsafe endpoint for SAST to catch
app.post("/calc", (req, res) => {
  const expr = req.body?.expr || "1+1";
  // DO NOT DO THIS IN REAL LIFE — intentionally unsafe for demo
  const result = eval(expr);
  res.json({ expr, result });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));