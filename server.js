const express = require("express");
const app = express();
const dotenv = require("dotenv");
const morgan = require("morgan");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");
const path = require("path");
const cors = require("cors");

// Load environment variables
dotenv.config();

// Connect to the database
connectDB();

// Middleware to serve static files (for image/file uploads)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Increase payload size limit
app.use(express.urlencoded({ limit: '50mb', extended: true })); // For URL-encoded data
app.use(cookieParser());
app.use(morgan("dev"));
// Routes
const authRoutes = require("./routes/authRoute");
app.use("/api/v1/auth", authRoutes);
// Default Route
app.use("/", (req, res) => {
    res.json({ message: "1 2 3 and boom guys" });
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
