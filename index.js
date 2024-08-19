require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('./passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { User, Movie } = require('./models');
const { validationResult, body } = require('express-validator');

const app = express();

// Setup middlewares
app.use(morgan('common')); // Logging
app.use(express.static(path.join(__dirname, 'public'))); // Serving static files
app.use(bodyParser.json()); // Middleware to parse JSON request bodies

// CORS configuration
app.use(cors());


// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.catch(err => {
    console.error('MongoDB connection error:', err);
});

// Initialize passport
app.use(passport.initialize());

// Middleware to require authentication
const requireAuth = passport.authenticate('jwt', { session: false });

// Middleware to handle validation errors
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).json({ errors: errors.array() });
    }
    next();
};

// Login route with validation
app.post('/login', 
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    validate,
    async (req, res) => {
        const { username, password } = req.body;

        try {
            const user = await User.findOne({ username });
            if (!user) {
                return res.status(401).send('Invalid username or password');
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).send('Invalid username or password');
            }

            const token = jwt.sign(
                { _id: user._id },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            res.json({ token });
        } catch (err) {
            console.error(err);
            res.status(500).send('Error: ' + err);
        }
    }
);

// Register new users with validation
app.post('/users', 
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    body('email').isEmail().withMessage('Email is invalid'),
    validate,
    async (req, res) => {
        try {
            // const hashedPassword = await bcrypt.hash(req.body.password, 10); remove this to avooid double hashing
            const user = await User.create({
                username: req.body.username,
                password: req.body.Password,
                email: req.body.email,
                birthday: req.body.birthday
            });
            res.status(201).json(user);
        } catch (err) {
            console.error(err);
            res.status(500).send('Error: ' + err);
        }
    }
);

// Update user with validation
app.put('/users/:username', requireAuth, 
    body('email').optional().isEmail().withMessage('Email is invalid'),
    validate,
    async (req, res) => {
        try {
            let updatedData = {
                email: req.body.email,
                birthday: req.body.birthday
            };
            
            if (req.body.username) {
                updatedData.username = req.body.username;
            }
            
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
    }
);

// Add movie to user's favorites
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

// Retrieve user details
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

// Retrieve movies with authentication
app.get('/movies', 
    passport.authenticate('jwt', { session: false }), 
    async (req, res) => {
        const limit = parseInt(req.query.limit) || 10;
        try { 
            const movies = await Movie.find().limit(limit).exec();
            res.json(movies);
        } catch (err) {
            console.error(err);
            res.status(500).send('Error: ' + err);
        }
    }
);

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
