const db = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
// Load environment variables
require('dotenv').config();
const invalidatedTokens = [];//logout api use
exports.register = async (req, res) => {
    const { username, password, email, phone } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ message: 'Please provide username, password, and email' });
    }

    try {
        // Ch[eck if the user already exists
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
};
// Registration Route
exports.login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [username]);

        if (results.length === 0) {
            return res.status(404).json({ status: 404, message: 'User not found' });

        }

        const user = results[0];
        const passwordIsValid = await bcrypt.compare(password, user.password);

        if (!passwordIsValid) {
            return res.status(401).send('Invalid password');
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: 86400 });

        res.status(200).send({ token });
    } catch (err) {
        console.error('Server error', err);
        res.status(500).send('Server error');
    }
};

exports.user = async (req, res) => {
    try {
        const [results] = await db.query('SELECT id, email, name FROM users WHERE id = ?', [req.user.id]);
        if (results.length === 0) {
            return res.status(404).json({ status: 404, message: 'User not found' });
        }

        const user = results[0];
        const user1 = req;
        res.status(200).json({ status: 200, user });
    } catch (err) {
        console.error('Server error', err);
        res.status(500).json({ status: 500, message: 'Server error' });
    }
};
//create
exports.create = async (req, res) => {
    const { title, des } = req.body;
    if (!title || !des) {
        return res.status(400).json({ message: 'Please provide title, description' });
    }

    try {
        const user_id = req.user.id;
        await db.query('INSERT INTO posts (title,description,created_by) VALUES (?, ?, ?)', [
            title,
            des,
            user_id,
        ]);

        res.status(201).json({ message: 'New post Created successfully' });
    } catch (err) {
        console.error('Server error', err);
        res.status(500).json({ status: 500, message: 'Server error' });
    }
};
exports.getpost = async (req, res) => {
    const { title, des } = req.body;
    try {
        const user_id = req.user.id; // Get the current user's ID

        const [results] = await db.query(`
        SELECT 
        posts.id AS post_id, 
        posts.title, 
        posts.description, 
        users.name AS created_by,
        COALESCE(likes.status, 0) AS like_status,
        (SELECT COUNT(*) FROM likes WHERE likes.post_id = posts.id) AS total_likes
    FROM posts
    JOIN users ON posts.created_by = users.id
    LEFT JOIN likes ON posts.id = likes.post_id AND likes.user_id = ?
    ORDER BY posts.id DESC
`, [user_id]);

        if (results.length === 0) {
            return res.status(404).json({ status: 404, message: 'Post not found' });
        }

        const postlist = results;

        res.status(200).json({ status: 200, postlist });
    } catch (err) {
        console.error('Server error', err);
        res.status(500).json({ status: 500, message: 'Server error' });
    }
};

////////////////////logoutuser api
exports.logoutuser = (req, res) => {
    const token = req.header('Authorization')?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ status: 401, message: 'No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Here you can add the token to a blacklist (not shown) or manage sessions
        invalidatedTokens.push(token);

        res.status(200).json({ status: 200, message: 'Logout successful' });
    } catch (err) {
        res.status(400).json({ status: 400, message: 'Invalid token.' });
    }
};

////////////////like//////////////////////////////
exports.like = async (req, res) => {
    const { post_id, status } = req.body;
    if (!post_id || status === undefined) {
        return res.status(400).json({ message: 'Please provide post_id and status' });
    }

    try {
        const user_id = req.user.id;

        // Check if the like already exists
        const [existingLike] = await db.query('SELECT * FROM likes WHERE post_id = ? AND user_id = ?', [post_id, user_id]);

        if (existingLike.length > 0) {
            // If the like exists, update the status
            await db.query('UPDATE likes SET status = ? WHERE post_id = ? AND user_id = ?', [status, post_id, user_id]);
            res.status(200).json({ message: 'Like status updated successfully' });
        } else {
            // If the like does not exist, insert a new like
            await db.query('INSERT INTO likes (post_id, user_id, status) VALUES (?, ?, ?)', [post_id, user_id, status]);
            res.status(201).json({ message: 'Like added successfully' });
        }
    } catch (err) {
        console.error('Server error', err);
        res.status(500).json({ status: 500, message: 'Server error' });
    }
};
///////////////////commnet////////////////////////////////////////////////////////////
exports.comment = async (req, res) => {
    const { post_id, comment, type } = req.body;
    const comment_at = new Date();
    if (!post_id || !comment) {
        return res.status(400).json({ message: 'Please provide post_id and comment' });
    }

    try {
        const user_id = req.user.id;

        await db.query('INSERT INTO omments (post_id, user_id, comment,comment_at) VALUES (?, ?, ?, ?, ?)', [post_id, user_id, comment, comment_at]);
        res.status(201).json({ message: 'Comment added successfully' });

    } catch (err) {
        console.error('Server error', err);
        res.status(500).json({ status: 500, message: 'Server error' });
    }
};
