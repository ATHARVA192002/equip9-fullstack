const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key';


app.use(express.json());
app.use(express.static('public'));


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'equip9_test'
});

db.connect(err => {
  if (err) throw err;
  console.log('Database connected!');
});


const createTableQuery = `CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  first_name VARCHAR(50),
  last_name VARCHAR(50),
  mobile_number VARCHAR(15),
  password VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_by VARCHAR(50),
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  updated_by VARCHAR(50)
)`;

db.query(createTableQuery, (err) => {
  if (err) throw err;
  console.log('Users table ready!');
});


app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.post('/register', async (req, res) => {
  const { firstName, lastName, mobileNumber, password } = req.body;
  if (!firstName || !lastName || !mobileNumber || !password) {
    return res.status(400).send('All fields are required.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const query = `INSERT INTO users (first_name, last_name, mobile_number, password, created_by) VALUES (?, ?, ?, ?, 'system')`;
  db.query(query, [firstName, lastName, mobileNumber, hashedPassword], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Registration failed.');
    }
    res.status(201).send('Registration successful!');
  });
});


app.post('/login', (req, res) => {
  const { mobileNumber, password } = req.body;
  if (!mobileNumber || !password) {
    return res.status(400).send('Mobile number and password are required.');
  }

  const query = `SELECT * FROM users WHERE mobile_number = ?`;
  db.query(query, [mobileNumber], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Login failed.');
    }
    if (results.length === 0) {
      return res.status(404).send('User not found.');
    }

    const user = results[0];
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).send('Invalid credentials.');
    }

    const token = jwt.sign({ id: user.id, firstName: user.first_name, lastName: user.last_name }, SECRET_KEY, {
      expiresIn: '1h'
    });

    res.status(200).json({ message: `Good Morning/Afternoon/Evening Mr. ${user.first_name} ${user.last_name}`, token });
  });
});


function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Access denied.');

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).send('Invalid token.');
    req.user = user;
    next();
  });
}


app.post('/logout', authenticateToken, (req, res) => {
  res.status(200).send('Logged out successfully!');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});