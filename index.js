const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const passport = require("passport");
const cookieSession = require("cookie-session");
const { Strategy } = require("passport-google-oauth20");
// const { verify } = require("crypto");

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

// While this function looks unnecessary because oauth assures us that the accessToken and profile will be valid, if we were supposed to implement authentication ourselves, this is where we would verify the details entered by the user
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("Google profile", profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Saving the session to the cookie
// done is a callback that helps us make asynchronous calls. Just like next()
passport.serializeUser((user, done) => {
  console.log("Serialise user!");
  done(null, user.id); // user is the value of the cookie
});

// Loading the session from the cookie
// Returns the data that'll be made available in req.user
passport.deserializeUser((id, done) => {
  done(null, id); // null because there are no errors. The second argument is the result that should go in req.user
});

const app = express();

app.use(helmet());
app.use(
  cookieSession({
    name: "session",
    maxAge: 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2], // used for signing the cookie
  })
);
app.use(passport.initialize());
app.use(passport.session()); // authenticates the session by informing passport about it. Passport now does all the siginin and saving and everything related to cookies

const PORT = 3000;

function checkLoggedIn(req, res, next) {
  console.log("Current user: ", req.user);
  const isLoggedIn = req.isAuthenticated && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "You must log in!",
    });
  }
  next();
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["email"], // the data we're requesting from google when everything succeeds
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true, // this will save the session. We can remove the parameter altogether as the default value is true
  }),
  (req, res) => {
    console.log("Google called us back!");
  }
);

app.get("failure", (req, res) => res.send("Fail to log in"));

app.get("/auth/logout", (req, res) => {});

app.get("/secret", checkLoggedIn, (req, res) => {
  res.send("Secret");
});

// https
//   .createServer(
//     {
//       key: fs.readFileSync("key.pem"),
//       cert: fs.readFileSync("cert.pem"),
//     },
//     app
//   )
//   .listen(PORT, () => console.log(`Server running on port ${PORT}`));

http
  .createServer(app)
  .listen(PORT, () => console.log(`Server running on port ${PORT}`));
