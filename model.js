const mongoose = require("mongoose");
const modelSchema = mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});

module.exports = mongoose.model("Model", modelSchema);
