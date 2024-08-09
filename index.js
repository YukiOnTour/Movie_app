// index.js
const express = require('express');
const morgan = require('morgan');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');  // Import CORS
const passport = require('./passport'); // Import your passport configuration
const auth = require('./auth'); // Ensure this points to your auth.js file
const { body, validationResult } = require('express-validator'); // Import express-validator

const app = express();

app.use(morgan('common'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(cors());  // Use CORS middleware

// Connect to MongoDB
mongoose.connect('mongodb+srv://yukiontour:Test.123@cluster0.vimspko.mongodb.net/sample_mflix?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('MongoDB connected successfully to Atlas');
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
    body('username').isLength({ min: 5 }).withMessage('Username must be at least 5 characters long'),
    body('password').isLength({ min: 5 }).withMessage('Password must be at least 5 characters long'),
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
app.post('/users', userValidationRules, validate, (req, res) => {
    console.log('Registering new user');
    User.create({
        username: req.body.username,
        password: req.body.password,
        email: req.body.email,
        birthday: req.body.birthday
    })
        .then(user => res.status(201).json(user))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

// Authentication route
require('./auth')(app);

// Update user with validation
app.put('/users/:username', requireAuth, userValidationRules, validate, (req, res) => {
    console.log(`Updating user with username: ${req.params.username}`);
    User.findOneAndUpdate({ username: req.params.username }, {
        $set: {
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            birthday: req.body.birthday
        }
    }, { new: true })
        .then(user => res.json(user))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

// Other protected routes...

app.get('/movies', requireAuth, (req, res) => {
    console.log('Fetching all movies');
    Movie.find()
        .then(movies => res.json(movies))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

app.get('/movies/:title', requireAuth, (req, res) => {
    console.log(`Fetching movie with title: ${req.params.title}`);
    Movie.findOne({ title: req.params.title })
        .then(movie => res.json(movie))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

app.get('/genres/:name', requireAuth, (req, res) => {
    console.log(`Fetching genre with name: ${req.params.name}`);
    Movie.findOne({ 'genre.name': req.params.name })
        .then(movie => {
            if (!movie) {
                return res.status(404).send('Genre not found');
            }
            res.json(movie.genre);
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

app.get('/directors/:name', requireAuth, (req, res) => {
    console.log(`Fetching director with name: ${req.params.name}`);
    Movie.findOne({ 'director.name': req.params.name })
        .then(movie => {
            if (!movie) {
                return res.status(404).send('Director not found');
            }
            res.json(movie.director);
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

app.get('/users', requireAuth, (req, res) => {
    console.log('Fetching all users');
    User.find()
        .then(users => res.json(users))
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

app.get('/users/:username', requireAuth, (req, res) => {
    console.log(`Fetching user with username: ${req.params.username}`);
    User.findOne({ username: req.params.username })
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

app.post('/users', (req, res) => {
    console.log('Registering new user');
    User.create({
        username: req.body.username,
        password: req.body.password,
        email: req.body.email,
        birthday: req.body.birthday
    })
    .then(user => res.status(201).json(user))
    .catch(err => {
        console.error(err);
        res.status(500).send('Error: ' + err);
    });
});

app.put('/users/:username', requireAuth, (req, res) => {
    console.log(`Updating user with username: ${req.params.username}`);
    User.findOneAndUpdate({ username: req.params.username }, {
        $set: {
            username: req.body.username,
            password: req.body.password,
            email: req.body.email,
            birthday: req.body.birthday
        }
    }, { new: true })
    .then(user => res.json(user))
    .catch(err => {
        console.error(err);
        res.status(500).send('Error: ' + err);
    });
});

app.post('/users/:username/movies/:movieID', requireAuth, (req, res) => {
    console.log(`Adding movie to favorites for user: ${req.params.username}`);
    User.findOneAndUpdate({ username: req.params.username }, {
        $push: { favoriteMovies: req.params.movieID }
    }, { new: true })
    .then(user => res.json(user))
    .catch(err => {
        console.error(err);
        res.status(500).send('Error: ' + err);
    });
});

app.delete('/users/:username/movies/:movieID', requireAuth, (req, res) => {
    console.log(`Removing movie from favorites for user: ${req.params.username}`);
    User.findOneAndUpdate({ username: req.params.username }, {
        $pull: { favoriteMovies: req.params.movieID }
    }, { new: true })
    .then(user => res.json(user))
    .catch(err => {
        console.error(err);
        res.status(500).send('Error: ' + err);
    });
});

app.delete('/users/:username', requireAuth, (req, res) => {
    console.log(`Deleting user with username: ${req.params.username}`);
    User.findOneAndDelete({ username: req.params.username })
        .then(user => {
            if (!user) {
                return res.status(404).send(`${req.params.username} was not found.`);
            }
            res.status(200).send(`${req.params.username} was deleted.`);
        })
        .catch(err => {
            console.error(err);
            res.status(500).send('Error: ' + err);
        });
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
