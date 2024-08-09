# myFlix API

Welcome to the `myFlix` API repository! This API provides access to movie data, user management, and allows users to manage their favorite movies.

## Features

- **Movies**: Retrieve, create, and manage movies.
- **Users**: Register, update user information, and manage favorite movies.

## API Endpoints

### Movies

- **GET** `/movies` - List all movies
- **GET** `/movies/:id` - Retrieve a single movie by ID
- **POST** `/movies` - Create a new movie

### Users

- **POST** `/users` - Register a new user
- **PUT** `/users/:username` - Update user information
- **POST** `/users/:username/movies/:movieID` - Add a movie to favorites
- **DELETE** `/users/:username/movies/:movieID` - Remove a movie from favorites
- **DELETE** `/users/:username` - Deregister a user

## Data Models

### Movie

- **title**: `string` - Title of the movie
- **description**: `string` - Description of the movie
- **genre**: Object - Genre details
  - **name**: `string` - Genre name
  - **description**: `string` - Genre description
- **director**: Object - Director details
  - **name**: `string` - Director name
  - **bio**: `string` - Director biography
  - **birthYear**: `number` - Director birth year
- **imageURL**: `string` - URL of the movie image
- **featured**: `boolean` - Whether the movie is featured

### User

- **username**: `string` - Unique username for the user
- **password**: `string` - User password (hashed)
- **email**: `string` - User email address
- **birthday**: `date` - User birthday
- **favoriteMovies**: Array of `ObjectId` - List of favorite movie IDs

## Getting Started

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/myFlix.git
   cd myFlix

2. **Install Dependencies**

   ```bash
   npm install


3. **Run the Server**
   ```bash
   npm start

## Contributing
Feel free to submit issues or pull requests if you find any bugs or have suggestions for improvements.

