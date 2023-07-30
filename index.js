// An open source phone-banking software, designed for the 21st century. https://github.com/xylactic/OpenCall

// Import dependencies
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const db = require('better-sqlite3')('database.db');
const bcrypt = require('bcrypt');
const session = require('express-session');
const config = require('./config.json');
const ejs = require('ejs');

// Create express app
const app = express();

// Set up body parser
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Set up session
app.use(session({
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

if (!config.adminEmail) {
    throw new Error('Please set the admin email in the config file.');
}

// Set up db
db.prepare('CREATE TABLE IF NOT EXISTS users (email TEXT, password TEXT, fname TEXT, lname TEXT)').run();
db.prepare('CREATE TABLE IF NOT EXISTS admins (email TEXT, permissions TEXT)').run();
// insert the admin in the config file into the database if not exists
const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(config.adminEmail);

if (!admin) {
    db.prepare('INSERT INTO admins VALUES (?, ?)').run(config.adminEmail, 'manageUsers&manageEvents');
}


// Set up static files
app.use(express.static(path.join(__dirname, 'public')));

// Set up routes
app.use('/pb', (req, res, next) => {
    if (req.session.user) {
        res.render('pb');
    } else {
        res.redirect('/login');
    }
});

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    if (req.session.user) {
        res.redirect('/pb');
    } else {
        res.render('login');
    }
});

app.post('/login', (req, res) => {
    let email = req.body.email;
    email = email.replace(/[^a-zA-Z0-9@.]/g, '');
    let password = req.body.password;
    password = password + config.salt;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                req.session.user = user;
                res.redirect('/pb');
            } else {
                res.render('login', { error: 'Incorrect password.' });
            }
        });
    } else {
        res.render('login', { error: 'Email not found' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/register', (req, res) => {
    if (req.session.user) {
        res.redirect('/pb');
    } else {
        res.render('register');
    }
});

app.post('/register', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;
    let fname = req.body.fname;
    let lname = req.body.lname;

    email = email.replace(/[^a-zA-Z0-9@.]/g, '');
    fname = fname.replace(/[^a-zA-Z0-9]/g, '');
    lname = lname.replace(/[^a-zA-Z0-9]/g, '');

    password = password + config.salt;

    if (!password || !fname || !lname || !email) {
        res.render('register', { error: 'Please fill out all fields.' });
        return
    }

    // regex test the email to make sure it's valid
    if (!email.match(/^[^@]+@[^@]+\.[^@]+$/)) {
        res.render('register', { error: 'Please enter a valid email.' });
        return
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (user) {
        res.render('register', { error: 'Email already in use.' });
        return
    }

    bcrypt.hash(password, 10, (err, hash) => {
        db.prepare('INSERT INTO users VALUES (?, ?, ?, ?)').run(email, hash, fname, lname);
        res.redirect('/login');
        return
    });
});


// admin page
app.get('/admin', (req, res) => {
    if (req.session.user) {
        const admin = db.prepare('SELECT * FROM admins WHERE email = ?').get(req.session.user.email);
        if (admin) {
            return res.render('admin', { permissionsStr: admin.permissions });
        } else {
            res.redirect('/pb');
        }
    } else {
        res.redirect('/login');
    }
});


// Start server
app.listen(config.port, () => {
    console.log(`OpenCall is now listening on port ${config.port}.`);
});