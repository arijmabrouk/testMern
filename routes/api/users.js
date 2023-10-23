const router = require("express").Router();
const bcrypt = require("bcryptjs");
const config = require("config");
const jwt = require("jsonwebtoken");
const auth = require("../../middleware/auth");
const User = require("../../models/User");

// @route POST api/users
// @desc Register new user
// @access Public
router.post("/register", (req, res) => {
  let { name, email, password, role = "user" } = req.body;

  if (!name || !email || !password || !role)
    return res.status(400).send({ msg: "Please enter all data" });

  User.findOne({ email: email }).then((user) => {
    if (user) return res.status(400).send({ msg: "Email already exist" });
  });

  let newUser = new User({ name, email, password, role });

  bcrypt.genSalt(10, (err, salt) => {
    if (err) throw err;
    bcrypt.hash(newUser.password, salt, (err, hash) => {
      if (err) throw err;
      newUser.password = hash;
      newUser.save().then((user) => {
        jwt.sign(
          { id: user.id },
          config.get("jwtSecret"),
          { expiresIn: config.get("tokenExpire") },
          (err, token) => {
            if (err) throw err;
            res.json({
              token,
              user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
              },
            });
          }
        );
      });
    });
  });
});
module.exports = router;
