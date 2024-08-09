const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const router = express.Router();
const { User } = require('./models');

router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err || !user) {
            return res.status(400).json({
                message: 'Something is not right',
                user: user
            });
        }
        req.login(user, { session: false }, (err) => {
            if (err) {
                res.send(err);
            }
            // generate a signed json web token with the contents of user object and return it in the response
            const token = jwt.sign(user.toJSON(), 'your_jwt_secret');
            return res.json({ user, token });
        });
    })(req, res);
});

module.exports = (app) => {
    app.use('/auth', router);
};
