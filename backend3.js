const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto'); // Import crypto for generating short ID
require('dotenv').config();

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
    eventType: String,  // ✅ Add Event Type here
    clubDepartmentName: String,
    description: String,
    registrationLink: String,
    image: String,
    status: { type: Number, default: 0 },  // Default status
    remarks: { type: String, default: "" }, // Default remarks
    requestedBy: String,
    approvedAt: { type: Date } // Received from frontend
});

// ✅ Use "requests" collection instead of default "events"
const Event = mongoose.model('requests', eventSchema);

const storage = multer.memoryStorage();
const upload = multer({ storage });
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

app.post("/api/events", async (req, res) => {
    console.log("🔍 Incoming POST request to /api/events");
    console.log("📥 Request Body:", req.body);

    const { filters, search } = req.body;
    let query = { status: 1 };

    if (filters?.length > 0) {
        console.log("✅ Processing Filters:", filters);

        // Standard event types
        const validEventTypes = ["Workshop", "Hackathon", "Competition", "Other"];
        
        let selectedEventTypes = filters
            .map(f => f.toLowerCase().trim()) // Normalize input (lowercase + trim spaces)
            .filter(f => validEventTypes.map(e => e.toLowerCase()).includes(f)) // Keep valid types
            .map(f => validEventTypes.find(e => e.toLowerCase() === f)); // Convert back to correct case

        if (selectedEventTypes.length > 0) {
            query.eventType = { $in: selectedEventTypes };
        }

        // 🗓️ Date filter (Next 2 weeks)
        if (filters.includes("date") || filters.includes("Date")) {
            let today = new Date();
            let twoWeeksLater = new Date();
            twoWeeksLater.setDate(today.getDate() + 14);

            query.eventDate = {
                $gte: today.toISOString().split("T")[0], // Format YYYY-MM-DD
                $lte: twoWeeksLater.toISOString().split("T")[0] 
            };

            console.log("📅 Filtering by date (Next 2 weeks)");
        }
    }

    if (search) {
        query.$or = [
            { eventName: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
            { clubDepartmentName: { $regex: search, $options: "i" } }
        ];
    }

    console.log("🔎 Final MongoDB Query:", JSON.stringify(query, null, 2));

    try {
        const events = await Event.find(query);
        res.json(events);
    } catch (error) {
        console.error("❌ Error fetching events:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});

//notification
app.get("/api/notifications", async (req, res) => {
    try {
        // Calculate the date 7 days ago
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        // Fetch events approved within the last 7 days
        const newEvents = await Event.find({
            status: 1, // Approved events only
            approvedAt: { $gte: sevenDaysAgo } // Approved within the last 7 days
        }).select("eventName approvedAt"); // Fetch only necessary fields

        // Format notifications
        const notifications = newEvents.map(event => ({
            message: `New event '${event.eventName}' published.`,
            approvedAt: event.approvedAt
        }));

        res.json({ notifications });

    } catch (error) {
        console.error("❌ Error fetching notifications:", error);
        res.status(500).json({ message: "Server error", error });
    }
});











// ✅ Upload Event API with New Fields
app.post('/api/notices/upload', upload.single('image'), async (req, res) => {
    try {
        console.log("📥 Received POST request to /api/notices/upload");
        console.log("📝 Received Data:", req.body);

        const { eventDate, eventTime, eventVenue, requestedBy } = req.body;
        const eventDateObj = new Date(eventDate);
        const today = new Date();
        today.setHours(0, 0, 0, 0); // Reset time to start of the day

        // ✅ Check if the event date is in the past
        if (eventDateObj < today) {
            console.log("⚠️ Error: Event date cannot be in the past.");
            return res.status(400).json({ message: 'Error: Event date cannot be in the past.' });
        }

        // ✅ Check for duplicate event (same date, time, and venue)
        const existingEvent = await Event.findOne({ eventDate, eventTime, eventVenue });

        if (existingEvent) {
            console.log("⚠️ Error: Duplicate event found.");
            return res.status(400).json({ message: 'Error: An event already exists at the same date, time, and venue.' });
        }

        // ✅ Generate a Short Unique event_id (6-character hexadecimal)
        let event_id;
        let isUnique = false;

        while (!isUnique) {
            event_id = crypto.randomBytes(3).toString('hex'); // Generates a 6-character ID
            const existingID = await Event.findOne({ event_id });
            if (!existingID) isUnique = true; // Ensure it's unique
        }

        // ✅ Proceed with event creation
        const newEvent = new Event({
            event_id,
            ...req.body,
            image: req.file ? req.file.buffer.toString('base64') : "",
            status: 0,    // Default status
            remarks: "",  // Default remarks
            requestedBy   // Received from frontend
        });

        await newEvent.save();
        console.log("✅ Event saved successfully in 'requests' collection!");

        res.status(201).json({ message: 'Event Added Successfully!', event_id });
    } catch (error) {
        console.error("❌ Server Error:", error);
        res.status(500).json({ message: 'Server Error', error });
    }
});
app.get("/api/notices", async (req, res) => {
    try {
        console.log("📥 Received GET request for events");

        let { department } = req.query;
        let query = {};

        if (department && department !== "All") {
            department = department.trim(); // Remove extra spaces
            query = { clubDepartmentName: { $regex: new RegExp(`^${department}$`, "i") } }; // Case-insensitive match
        }

        const events = await Event.find(query);
        console.log(`✅ Sending ${events.length} events for department: ${department || "All"}`);

        res.json(events);
    } catch (error) {
        console.error("❌ Error fetching events:", error);
        res.status(500).json({ message: "Server Error", error });
    }
});
app.put("/api/notices/:eventId", async (req, res) => {
    try {
        const eventId = req.params.eventId;
        const { status } = req.body;

        // 🟢 Log incoming request details
        console.log(`🔹 Received PUT request for event: ${eventId}`);
        console.log(`🔹 Request Body:`, req.body);

        // Validate status (should be either 1 or 2)
        if (![1, 2].includes(status)) {
            console.log("❌ Invalid status value received:", status);
            return res.status(400).json({ message: "Invalid status value. Use 1 for Approved, 2 for Rejected." });
        }

        // Ensure eventId is a valid ObjectId
        if (!mongoose.Types.ObjectId.isValid(eventId)) {
            console.log("❌ Invalid event ID format:", eventId);
            return res.status(400).json({ message: "Invalid event ID format." });
        }

        // Set approvedAt only if status is 1 (approved)
        const updateFields = { status };
        if (status === 1) {
            updateFields.approvedAt = new Date();
        }

        // Find and update event
        const updatedEvent = await Event.findByIdAndUpdate(
            eventId,
            updateFields,
            { new: true } // Return the updated document
        );

        if (!updatedEvent) {
            console.log(`❌ Event not found with ID: ${eventId}`);
            return res.status(404).json({ message: "Event not found." });
        }

        console.log(`✅ Event ${eventId} updated successfully. New Status: ${status}`);
        res.json({ message: "Event status updated successfully.", event: updatedEvent });

    } catch (error) {
        console.error("❌ Server error while updating event:", error);
        res.status(500).json({ message: "Server error", error });
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
app.get("/api/getEvents", async (req, res) => {
    try {
        const events = await Event.find({ status: 1 });

        // Transform data to match frontend format
        const mappedData = events.map(event => ({
            place: event.eventVenue,
            title: event.eventName.split(" ")[0] || "",
            title2: event.eventName.split(" ")[1] || "",
            image: event.image, // Assuming image is stored as Base64
        }));

        res.json(mappedData);
    } catch (error) {
        console.error("Error fetching events:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});
// ✅ Start Server
app.listen(5004, () => console.log("🚀 Server running on http://localhost:5004"));
