const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

// Define the schema for the Genre subdocument
const genreSchema = new Schema({
  name: { type: String, required: true },
  description: { type: String, required: true }
});

// Define the schema for the Director subdocument
const directorSchema = new Schema({
  name: { type: String, required: true },
  bio: { type: String, required: true },
  birthYear: { type: Number, required: true }
});

// Define the main Movie schema
const movieSchema = new Schema({
  title: { type: String, required: true },
  plot: { type: String, required: true },
  genres: [String],  // Adjusted to match array of strings
  runtime: Number,
  cast: [String],  // Array of strings
  poster: { type: String, required: true },
  fullplot: { type: String, required: true },
  languages: [String],  // Array of strings
  released: Date,
  directors: [String],  // Array of strings
  rated: String,
  awards: {
    wins: Number,
    nominations: Number,
    text: String
  },
  year: Number,
  imdb: {
    rating: Number,
    votes: Number,
    id: Number
  },
  countries: [String],  // Array of strings
  type: String,
  tomatoes: {
    viewer: {
      rating: Number,
      numReviews: Number,
      meter: Number
    },
    fresh: Number,
    critic: {
      rating: Number,
      numReviews: Number,
      meter: Number
    },
    rotten: Number,
    lastUpdated: Date
  },
  num_mflix_comments: Number
});

// Define the User schema with bcrypt integration
const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  birthday: { type: Date, required: true },
  favoriteMovies: [{ type: Schema.Types.ObjectId, ref: 'Movie' }]
});

// Hash password before saving
userSchema.pre('save', function(next) {
  if (!this.isModified('password')) return next();
  bcrypt.hash(this.password, 10, (err, hash) => {
    if (err) return next(err);
    this.password = hash;
    next();
  });
});

// Compare password method
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

// Create the Movie and User models
const Movie = mongoose.model('Movie', movieSchema);
const User = mongoose.model('User', userSchema);

module.exports = { Movie, User };
