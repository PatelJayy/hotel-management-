const express = require("express");
const cors = require("cors");
const app = express();

require("dotenv").config();

app.use(express.json());
app.use(cors());

const authRouter = require("./authRouter");
app.use("/auth", authRouter);

const port = process.env.PORT || 3003;

app.listen(port, () => {
  console.log(`Authentication Server started on port ${port}`);
});
