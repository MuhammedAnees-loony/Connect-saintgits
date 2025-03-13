require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const crypto = require("crypto"); // Import crypto for generating short ID
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ✅ Define Schema for Requests Collection
const eventSchema = new mongoose.Schema({
    event_id: { type: String, unique: true },  // Short Unique event ID
    eventName: String,
    eventDate: String,
    eventTime: String,
    eventVenue: String,
    organizer: String,
    category: String,
    clubDepartmentName: String, // ✅ Added back Club/Department Name field
    description: String,
    registrationLink: String,
    image: String,
    status: { type: Number, default: 0 },  // Default status
    remarks: { type: String, default: "" }, // Default remarks
    requestedBy: String  // Received from frontend
});

// ✅ Use "requests" collection instead of default "events"
const Event = mongoose.model('requests', eventSchema);

// ✅ User Authentication Schema
const UserSchema = new mongoose.Schema({
    user_id: { type: String, unique: true, required: true },
    user_name: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ["admin", "organizer", "user"] },
});

// ✅ Use "users" collection in MongoDB
const User = mongoose.model("users", UserSchema);

// ✅ Login Route
app.post("/login", async (req, res) => {
    const { user_id, password } = req.body;
    console.log("📥 Login Attempt:", { user_id, password });

    try {
        const user = await User.findOne({ user_id });

        if (!user) {
            console.log("❌ User not found in DB");
            return res.status(400).json({ message: "❌ User not found" });
        }

        console.log("🔍 Found User:", user);

        // Compare provided password with hashed password in DB
        const isMatch = await bcrypt.compare(password, user.password);
        console.log("🔑 Password Match:", isMatch);

        if (!isMatch) {
            console.log("❌ Incorrect Password");
            return res.status(400).json({ message: "❌ Invalid password" });
        }

        // 🔑 Generate JWT Token
        const token = jwt.sign(
            { user_id: user.user_id, role: user.role, user_name: user.user_name }, 
            process.env.JWT_SECRET || "your_secret_key", 
            { expiresIn: "1h" }
        );

        console.log("✅ Token Generated:", token);

        // 🔀 Redirect based on role
        let redirectUrl = "/";
        if (user.role === "admin") {
            redirectUrl = `admin09.html?user_name=${encodeURIComponent(user.user_name)}`;
        } else if (user.role === "organizer") {
            redirectUrl = `upload.html?user_name=${encodeURIComponent(user.user_name)}`;
        }

        res.json({ token, role: user.role, redirectUrl });

    } catch (err) {
        console.error("❌ Login Error:", err);
        res.status(500).json({ message: "❌ Server Error" });
    }
});


const storage = multer.memoryStorage();
const upload = multer({ storage });

// ✅ Upload Event API with Club/Department Name
app.post('/api/notices/upload', upload.single('image'), async (req, res) => {
    try {
        console.log("📥 Received POST request to /api/notices/upload");
        console.log("📝 Full Request Body:", req.body); // ✅ Log the full request body

        const { eventDate, eventTime, eventVenue, requestedBy, clubDepartmentName } = req.body;

        if (!clubDepartmentName) {
            console.log("⚠️ Warning: Club/Department Name is missing from request!");
        }

        const eventDateObj = new Date(eventDate);
        const today = new Date();
        today.setHours(0, 0, 0, 0); 

        if (eventDateObj < today) {
            return res.status(400).json({ message: 'Error: Event date cannot be in the past.' });
        }

        const existingEvent = await Event.findOne({ eventDate, eventTime, eventVenue });

        if (existingEvent) {
            return res.status(400).json({ message: 'Error: An event already exists at the same date, time, and venue.' });
        }

        let event_id;
        let isUnique = false;

        while (!isUnique) {
            event_id = crypto.randomBytes(3).toString('hex'); 
            const existingID = await Event.findOne({ event_id });
            if (!existingID) isUnique = true; 
        }

        // ✅ Include clubDepartmentName in event creation
        const newEvent = new Event({
            event_id,
            eventName: req.body.eventName,
            eventDate,
            eventTime,
            eventVenue,
            organizer: req.body.organizer,
            category: req.body.category,
            clubDepartmentName, // ✅ Ensure it is being saved!
            description: req.body.description,
            registrationLink: req.body.registrationLink,
            image: req.file ? req.file.buffer.toString('base64') : "",
            status: 0,  
            remarks: "",  
            requestedBy  
        });

        await newEvent.save();
        console.log("✅ Event saved successfully in 'requests' collection!");
        res.status(201).json({ message: 'Event Added Successfully!', event_id });
    } catch (error) {
        console.error("❌ Server Error:", error);
        res.status(500).json({ message: 'Server Error', error });
    }
});

// ✅ Fetch Events API (From "requests" collection)
app.get('/api/notices', async (req, res) => {
    try {
        console.log("📤 Fetching all events from 'requests' collection...");
        const events = await Event.find();
        console.log("✅ Events fetched:", events.length, "records found.");
        res.json(events);
    } catch (error) {
        console.error("❌ Error fetching events:", error);
        res.status(500).json({ message: "Error fetching events" });
    }
});

// ✅ Fetch Events by Department API
app.get('/api/notices/department/:deptName', async (req, res) => {
    try {
        const { deptName } = req.params;
        console.log(`📤 Fetching events for department: ${deptName}`);

        const events = await Event.find({ clubDepartmentName: deptName });

        if (events.length === 0) {
            console.log("⚠️ No events found for this department.");
            return res.status(404).json({ message: "No events found for this department." });
        }

        console.log(`✅ Found ${events.length} event(s) for department: ${deptName}`);
        res.json(events);
    } catch (error) {
        console.error("❌ Error fetching events by department:", error);
        res.status(500).json({ message: "Error fetching events by department" });
    }
});


// ✅ Delete Event API
app.delete('/api/notices/:id', async (req, res) => {
    try {
        console.log("🗑️ Deleting event with ID:", req.params.id);
        await Event.findByIdAndDelete(req.params.id);
        console.log("✅ Event deleted successfully!");
        res.json({ message: "✅ Event Deleted" });
    } catch (error) {
        console.error("❌ Error deleting event:", error);
        res.status(500).json({ message: "Error deleting event" });
    }
});

// ✅ Start Server
const PORT = process.env.PORT || 5004;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
