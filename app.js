require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const { database } = require('./databaseConnection');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
    dbName: mongodb_database,
    crypto: { secret: mongodb_session_secret }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime }
}));

function isAuthenticated(req) {
    return req.session && req.session.authenticated;
}

function isAdmin(req) {
    return req.session && req.session.user_type === 'admin';
}

function sessionValidation(req, res, next) {
    if (isAuthenticated(req)) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render('403');
        return;
    }
    next();
}

// Home
app.get('/', (req, res) => {
    res.render('index', {
        authenticated: isAuthenticated(req),
        name: req.session.name
    });
});

// Signup form
app.get('/signup', (req, res) => {
    res.render('signup');
});

// Signup submit
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) {
        res.render('signupSubmit', { error: 'Name is required.' });
        return;
    }
    if (!email) {
        res.render('signupSubmit', { error: 'Please provide an email address.' });
        return;
    }
    if (!password) {
        res.render('signupSubmit', { error: 'Password is required.' });
        return;
    }

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        res.render('signupSubmit', { error: validationResult.error.details[0].message });
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = 'user';
    req.session.save(() => res.redirect('/members'));
});

// Login form
app.get('/login', (req, res) => {
    res.render('login');
});

// Login submit
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        res.render('loginSubmit', { error: 'Invalid email/password combination.' });
        return;
    }

    const result = await userCollection
        .find({ email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length !== 1) {
        res.render('loginSubmit', { error: 'Invalid email/password combination.' });
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.save(() => res.redirect('/members'));
        return;
    }

    res.render('loginSubmit', { error: 'Invalid email/password combination.' });
});

// Members
app.get('/members', (req, res) => {
    if (!isAuthenticated(req)) {
        res.redirect('/');
        return;
    }
    res.render('members', { name: req.session.name });
});

// Admin
app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection
        .find()
        .project({ name: 1, user_type: 1, _id: 1 })
        .toArray();
    res.render('admin', { users });
});

// Promote user
app.post('/admin/promote', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;

    const schema = Joi.string().max(50).required();
    const validationResult = schema.validate(username);
    if (validationResult.error) {
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne({ name: username }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
});

// Demote user
app.post('/admin/demote', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;

    const schema = Joi.string().max(50).required();
    const validationResult = schema.validate(username);
    if (validationResult.error) {
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne({ name: username }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Static files
app.use(express.static(__dirname + '/public'));

// 404
app.use((req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
