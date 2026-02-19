/**
 * BACKEND DOCUMENTATION:
 * This file handles the "Secure Handshake" between Google and our Application.
 * * CORE CONCEPTS:
 * 1. Networking: Using Express.js to listen for requests.
 * 2. Authentication: Using Passport.js to verify identity via Google.
 * 3. Authorization: Using JWT to issue a stateless "VIP Pass" once verified.
 */

require('dotenv').config(); // Loads our secret keys from .env
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// --- DEBUG CHECK: Run this to see if .env is working ---
if (!process.env.GOOGLE_CLIENT_ID) {
    console.error("❌ ERROR: GOOGLE_CLIENT_ID is missing! Check your .env file.");
    process.exit(1); // Stop the server immediately if keys are missing
}

// MIDDLEWARE: Serves the HTML files from the "public" folder
app.use(express.static('public'));

/**
 * PASSPORT CONFIGURATION (The Handshake Logic)
 * We tell Passport to use Google's Strategy to verify users.
 */
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,         // Our App's Username at Google
    clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Our App's Password at Google
    callbackURL: "/auth/google/callback"           // The "Return Address" Google sends users back to
  },
  (accessToken, refreshToken, profile, done) => {
    // This function runs AFTER the user logs into Google.
    // 'profile' contains the user's name and email.
    return done(null, profile);
  }
));

/**
 * ROUTES: THE NETWORKING LAYER
 */

// 1. THE TRIGGER: User clicks the "Sign in with Google" button.
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// 2. THE RECEIVER: Google sends the user back here with a secret code.
app.get('/auth/google/callback', 
  passport.authenticate('google', { session: false }), // No sessions = Stateless
  (req, res) => {
    
    /**
     * CYBERSECURITY FOCUS: ISSUING THE JWT
     */
    const payload = { 
        id: req.user.id, 
        name: req.user.displayName,
        email: req.user.emails[0].value 
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.send(`
        <div style="font-family: sans-serif; padding: 50px; text-align: center;">
            <h1 style="color: #003973;">Authorization Successful!</h1>
            <p>Google verified your identity. Here is your <strong>Stateless JWT:</strong></p>
            <textarea style="width: 100%; height: 150px; padding: 10px; background: #f4f4f4; border-radius: 8px; border: 1px solid #ddd;" readonly>${token}</textarea>
            <p style="color: #666; font-size: 0.8rem; margin-top: 20px;">This token can now be used to access protected data without checking a database.</p>
            <a href="/" style="text-decoration: none; color: #003973; font-weight: bold;">← Back to Home</a>
        </div>
    `);
  }
);

app.listen(PORT, () => {
    console.log(`🚀 Server is live at http://localhost:${PORT}`);
});