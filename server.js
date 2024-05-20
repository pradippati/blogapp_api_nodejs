// server.js
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const db = require('./config/db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Registration Route
app.post('/register1', async (req, res) => {
    const { username, password, email, phone } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ message: 'Please provide username, password, and email' });
    }

    try {
        // Check if the user already exists
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        await db.query('INSERT INTO users (name,email,phone,password) VALUES (?, ?, ?,?)', [
            username,
            email,
            phone,
            hashedPassword,
        ]);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
