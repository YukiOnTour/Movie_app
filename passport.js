// passport.js
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { User } = require('./models'); // Adjust the path as needed
const bcrypt = require('bcryptjs');

// Local Strategy
passport.use(new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
}, async (username, password, done) => {
    try {
        const user = await User.findOne({ username }).exec();
        if (!user) {
            return done(null, false, { message: 'Incorrect username.' });
        }
        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            return done(null, user);
        } else {
            return done(null, false, { message: 'Incorrect password.' });
        }
    } catch (err) {
        console.error('Error during authentication:', err);
        return done(err);
    }
}));

// JWT Strategy
const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET // Use environment variable for secret key
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
    try {
        const user = await User.findById(jwt_payload._id).exec();
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    } catch (err) {
        console.error('Error during JWT strategy:', err);
        return done(err, false);
    }
}));

// Serialize user information into sessions
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user information from sessions
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id).exec();
        done(null, user);
    } catch (err) {
        done(err);
    }
});

module.exports = passport;
