const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
  try {
    const token = req.headers["x-access-token"];
    if (!token) {
      res.send("you require a valid token..!");
    } else {
      jwt.verify(token, "jwtSecret", (err, decoded) => {
        if (err) {
          res.send({ auth: false, message: "Need valid token" });
        } else {
          req.userId = decoded.id;
          next();
        }
      });
    }
  } catch (err) {
    res.send({ auth: false, message: "No token found" });
  }
};

module.exports = verifyJWT;
