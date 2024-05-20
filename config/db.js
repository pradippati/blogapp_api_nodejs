const mysql = require('mysql2');

const pool = mysql.createConnection({
    host: 'localhost',
    user: 'root', // your MySQL username
    password: '', // your MySQL password
    database: 'blog'
});
pool.connect(err => {
    if (err) throw err;
    console.log('Connected to the MySQL server.');
});

module.exports = pool.promise();