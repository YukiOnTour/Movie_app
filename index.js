const express = require('express');
const morgan = require('morgan');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('./passport');
const auth = require('./auth');
const { body, validationResult } = require('express-validator');

const app = express();

app.use(morgan('common'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.catch(err => {
    console.error('MongoDB connection error:', err);
});

// Require your auth file
auth(app);

// Middleware to require authentication
const requireAuth = passport.authenticate('jwt', { session: false });

// Models
const { Movie, User } = require('./models');
const bcrypt = require('bcryptjs');

// Validation for user registration and update
const userValidationRules = [
    body('username')
        .isLength({ min: 5 }).withMessage('Username must be at least 5 characters long')
        .trim()
        .matches(/^\S+$/).withMessage('Username must not contain spaces'),
    body('password')
        .isLength({ min: 5 }).withMessage('Password must be at least 5 characters long')
        .matches(/^\S+$/).withMessage('Password must not contain spaces'),
    body('email').isEmail().withMessage('Email is not valid'),
    body('birthday').isDate().withMessage('Birthday must be a valid date')
];

// Middleware to handle validation errors
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }
    next();
};

// Register new users with validation
app.post('/users', userValidationRules, validate, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = await User.create({
            username: req.body.username,
            password: hashedPassword,
            email: req.body.email,
            birthday: req.body.birthday
        });
        res.status(201).json(user);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: ' + err);
    }
});

// Update user with validation
app.put('/users/:username', requireAuth, userValidationRules, validate, async (req, res) => {
    try {
        let updatedData = {
            username: req.body.username,
            email: req.body.email,
            birthday: req.body.birthday
        };
        
        // If password is provided, hash it
        if (req.body.password) {
            const hashedPassword = await bcrypt.hash(req.body.password, 10);
            updatedData.password = hashedPassword;
        }

        const user = await User.findOneAndUpdate(
            { username: req.params.username },
            { $set: updatedData },
            { new: true }
        ).select('-password'); // Exclude password from the returned user object

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: ' + err);
    }
});

// Add movie to user's favorites, preventing duplicates
app.post('/users/:username/movies/:movieID', requireAuth, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username });
        if (!user) {
            return res.status(404).send('User not found');
        }
        if (user.favoriteMovies.includes(req.params.movieID)) {
            return res.status(400).send('Movie is already in favorites');
        }
        user.favoriteMovies.push(req.params.movieID);
        await user.save();
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error: ' + err);
    }
});

// Retrieve user details, excluding password
app.get('/users/:username', requireAuth, (req, res) => {
    User.findOne({ username: req.params.username })
        .select('-password') // Exclude password from the returned user object
        .then(user => {
            if (!user) {
                return res.status(404).send('User not found');
            }
            res.json(user);
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

// Retrieve movies with a limit on the number of results
app.get('/movies', requireAuth, (req, res) => {
    // Get the 'limit' parameter from the query string, default to 10 if not provided
    const limit = parseInt(req.query.limit) || 10;

    Movie.find()
        .limit(limit)  // Limit the number of results returned
        .then(movies => res.json(movies))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

// Other protected routes...

const port = process.env.PORT || 8080;
app.listen(port);
