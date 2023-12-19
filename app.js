const express = require('express');
const mysql = require('mysql');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');

dotenv.config({ path: './.env' });

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE
});

db.connect((error) => {
  if (error) {
    console.log(error);
  } else {
    console.log("MYSQL connected...");
  }
});

app.post('/signup', (req, res) => {
  const username = req.body.name;
  const email = req.body.email;
  const password = req.body.password;

  // Hash the password before storing it in the database
  bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
    if (hashErr) {
      console.error("Error hashing password:", hashErr);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    const sql = "INSERT INTO user (username, email, password) VALUES (?, ?, ?)";
    const values = [username, email, hashedPassword];

    db.query(sql, values, (err, data) => {
      if (err) {
        console.error("Error inserting data:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }
      return res.json(data);
    });
  });
});

app.post('/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const sql = "SELECT id, email, password FROM user WHERE email=?";
  db.query(sql, [email], (err, data) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.json('Error');
    }

    if (data.length > 0) {
      const hashedPassword = data[0].password;

      // Compare the entered password with the hashed password
      bcrypt.compare(password, hashedPassword, (compareErr, passwordMatch) => {
        if (compareErr) {
          console.error("Error comparing passwords:", compareErr);
          return res.status(500).json({ error: "Internal Server Error" });
        }

        if (passwordMatch) {
          return res.json('Success');
        } else {
          return res.json('Failure');
        }
      });
    } else {
      return res.json('Failure');
    }
  });
});

app.get('/', (req, res) => {
  res.send('Welcome to your backend server!');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
