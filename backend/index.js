const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware to parse JSON data
app.use(bodyParser.json());

// Connect to your MongoDB database (change the connection string and database name)
mongoose.connect('mongodb://localhost/food_delivery_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB database');
});

// Define a User Schema and Model
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  // Add more fields as needed (e.g., name, address, etc.)
});

const User = mongoose.model('User', userSchema);

const restaurantSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  location: {
    type: String,
    required: true,
  },
  menu: [
    {
      foodItem: String,
      price: Number,
      type: String,
      itemImage: String, // You can store the image URL
    },
  ],
  // Add a password field to protect restaurant access
  password: {
    type: String,
    required: true,
  },
});

const Restaurant = mongoose.model('Restaurant', restaurantSchema);

// Signup route
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if the username or email already exists
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already in use' });
    }

    // Create a new user and hash the password securely
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    res.json({ message: 'User registration successful' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });

    // Check if the user exists
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Use bcrypt to securely compare hashed passwords
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      // Generate a JWT token for authentication
      const token = jwt.sign({ userId: user._id }, 'your_secret_key', { expiresIn: '1h' });

      res.json({ message: 'Login successful', token });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Signup route for restaurants
app.post('/api/restaurant/signup', async (req, res) => {
  try {
    const { name, password, description, location, menu } = req.body;

    // Create a new restaurant and hash the password securely
    const hashedPassword = await bcrypt.hash(password, 10);
    const newRestaurant = new Restaurant({
      name,
      password: hashedPassword,
      description,
      location,
      menu,
    });

    await newRestaurant.save();
    res.json({ message: 'Restaurant registration successful' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to register restaurant' });
  }
});

// Login route for restaurants
app.post('/api/restaurant/login', async (req, res) => {
  try {
    const { name, password } = req.body;

    // Find the restaurant by name
    const restaurant = await Restaurant.findOne({ name });

    // Check if the restaurant exists
    if (!restaurant) {
      return res.status(401).json({ error: 'Invalid restaurant name or password' });
    }

    // Use bcrypt to securely compare hashed passwords
    const passwordMatch = await bcrypt.compare(password, restaurant.password);

    if (passwordMatch) {
      // Generate a JWT token for restaurant authentication
      const token = jwt.sign({ restaurantId: restaurant._id }, 'your_restaurant_secret_key', { expiresIn: '1h' });

      res.json({ message: 'Restaurant login successful', token });
    } else {
      res.status(401).json({ error: 'Invalid restaurant name or password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Route for adding a restaurant (accessible to super users only)
app.post('/api/restaurant', async (req, res) => {
  try {
    // Check if the user is a superuser
    const { userId } = req.body;
    const user = await User.findById(userId);

    if (!user || !user.superuser) {
      return res.status(403).json({ error: 'Unauthorized access' });
    }

    // Extract restaurant data from the request body
    const { name, description, location, menu } = req.body;

    // Create a new restaurant document and save it to the database
    const newRestaurant = new Restaurant({
      name,
      description,
      location,
      menu,
    });

    await newRestaurant.save();
    res.json({ message: 'Restaurant added successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add a restaurant' });
  }
});

// Route for updating a restaurant's menu (accessible to super users or restaurant owners)
app.put('/api/update-menu/:restaurantId', async (req, res) => {
  try {
    // Check if the user is authorized (super user or restaurant owner)
    const { userId, role } = req.body;
    const user = await User.findById(userId);

    if (!user || (!user.superuser && user._id.toString() !== userId)) {
      return res.status(403).json({ error: 'Unauthorized access' });
    }

    // Extract menu data from the request body
    const { menu } = req.body;

    // Find and update the restaurant's menu
    const restaurantId = req.params.restaurantId;
    const restaurant = await Restaurant.findById(restaurantId);

    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant not found' });
    }

    // Update the menu of the restaurant
    restaurant.menu = menu;

    // Save the updated restaurant document
    await restaurant.save();

    res.json({ message: 'Menu updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update the menu' });
  }
});

// Route for deleting an item from a restaurant's menu (accessible to super users or restaurant owners)
app.delete('/api/delete-menu-item/:restaurantId/:itemId', async (req, res) => {
  try {
    // Check if the user is authorized (super user or restaurant owner)
    const { userId, role } = req.body;
    const user = await User.findById(userId);

    if (!user || (!user.superuser && user._id.toString() !== userId)) {
      return res.status(403).json({ error: 'Unauthorized access' });
    }

    // Find the restaurant
    const restaurantId = req.params.restaurantId;
    const restaurant = await Restaurant.findById(restaurantId);

    if (!restaurant) {
      return res.status(404).json({ error: 'Restaurant not found' });
    }

    // Find and remove the menu item
    const itemId = req.params.itemId;
    const menuItem = restaurant.menu.id(itemId);

    if (!menuItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }

    // Remove the menu item from the restaurant's menu
    menuItem.remove();

    // Save the updated restaurant document
    await restaurant.save();

    res.json({ message: 'Menu item deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete the menu item' });
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});