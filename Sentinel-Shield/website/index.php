<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelShield | Search Portal</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
:root {
  --bg: #0b0f1a;
  --card: rgba(255,255,255,0.08);
  --border: rgba(255,255,255,0.15);
  --accent: #00ffd5;
  --danger: #ff4d4d;
}

* {
  box-sizing: border-box;
  font-family: "Segoe UI", system-ui, sans-serif;
}

body {
  margin: 0;
  height: 100vh;
  background:
    radial-gradient(circle at top, #111827, #020617);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #e5e7eb;
}

.container {
  width: 90%;
  max-width: 800px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 40px;
  backdrop-filter: blur(14px);
  box-shadow: 0 0 40px rgba(0,0,0,0.6);
  animation: fadeIn 1.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(30px); }
  to { opacity: 1; transform: translateY(0); }
}

h1 {
  margin: 0;
  font-size: 2.5rem;
  text-align: center;
  background: linear-gradient(90deg, var(--accent), #7c7cff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

p.subtitle {
  text-align: center;
  opacity: 0.7;
  margin-top: 10px;
}

.search-box {
  margin-top: 40px;
  display: flex;
  gap: 15px;
}

input[type="text"] {
  flex: 1;
  padding: 16px 18px;
  font-size: 1rem;
  background: rgba(0,0,0,0.4);
  border: 1px solid var(--border);
  border-radius: 12px;
  color: white;
  outline: none;
  transition: 0.3s;
}

input[type="text"]:focus {
  border-color: var(--accent);
  box-shadow: 0 0 12px rgba(0,255,213,0.3);
}

button {
  padding: 16px 28px;
  font-size: 1rem;
  border-radius: 12px;
  border: none;
  cursor: pointer;
  background: linear-gradient(135deg, var(--accent), #7c7cff);
  color: #020617;
  font-weight: bold;
  transition: transform 0.2s, box-shadow 0.2s;
}

button:hover {
  transform: translateY(-2px);
  box-shadow: 0 10px 25px rgba(0,255,213,0.3);
}

.results {
  margin-top: 30px;
  padding: 20px;
  border-radius: 12px;
  background: rgba(0,0,0,0.35);
  border: 1px solid var(--border);
}

.warning {
  color: var(--danger);
  font-size: 0.9rem;
  opacity: 0.8;
}

.footer {
  margin-top: 25px;
  text-align: center;
  font-size: 0.85rem;
  opacity: 0.5;
}
</style>
</head>

<body>

<div class="container">
  <h1>SentinelShield</h1>
  <p class="subtitle">Web Search Interface (Monitored & Logged)</p>

  <form method="GET" action="">
    <div class="search-box">
      <input
        type="text"
        name="q"
        placeholder="Search products, users, files..."
        value="<?php echo isset($_GET['q']) ? $_GET['q'] : ''; ?>"
      >
      <button type="submit">Search</button>
    </div>
  </form>

  <div class="results">
    <strong>Search Results</strong>
    <hr style="border-color: rgba(255,255,255,0.1)">
    <p>
      You searched for:
      <br><br>
      <code>
        <?php
          if (isset($_GET['q'])) {
            echo $_GET['q'];
          } else {
            echo "Nothing yet.";
          }
        ?>
      </code>
    </p>

    <p class="warning">
      ⚠ This input is intentionally unfiltered for security testing.
    </p>
  </div>

  <div class="footer">
    SentinelShield Lab • Defensive Security Simulation
  </div>
</div>

</body>
</html>