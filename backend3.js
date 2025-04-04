const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"); // Import crypto for generating short ID
const { type } = require('os');
const session = require("express-session");
const cron = require('node-cron');
const nodemailer = require('nodemailer');
require('dotenv').config();


const app = express();
app.use(cors());
app.use(express.json());
app.use(session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Set `true` if using HTTPS
}));

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(async () => {
    console.log('✅ MongoDB Connected');
    await syncVenues(); // Sync venue data after connection
})
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1); // Exit process if connection fails
});

// ✅ Define Schema for Requests Collection
const eventSchema = new mongoose.Schema({
    event_id: { type: String, unique: true },
    user_id: { type: String,  required: true },  // Short Unique event ID
    eventName: { type: String, unique: true },
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
const UserSchema = new mongoose.Schema({
    user_id: { type: String, unique: true, required: true },
    user_name: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ["admin", "organizer", "user"] },
});
// Define Mongoose Schema
const EventVenueSchema = new mongoose.Schema({
    blockId: { type: String, required: true },
    eventName: { type: String, required: true },
    eventTime: { type: String, required: true },
    venue: { type: String, required: true },
    eventDate:{ type: String, required: true },
});

const News = mongoose.model("News", new mongoose.Schema({
    email: { type: String, unique: true, required: true }
}));
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.SMTP_EMAIL,
        pass: process.env.SMTP_PASSWORD
    }
})
const EventVenue = mongoose.model('venues', EventVenueSchema);

// ✅ Use "users" collection in MongoDB
const User = mongoose.model("users", UserSchema);

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
        const authHeader = req.headers.authorization;
        const token = authHeader.split(" ")[1];
        const { eventDate, eventTime, eventVenue, requestedBy } = req.body;
        const eventDateObj = new Date(eventDate);
        const today = new Date();
        const decoded = jwt.decode(token);
        if (!decoded) {
            return res.status(400).json({ message: "❌ Invalid token" });
        }
        const user_id = decoded.user_id;
        console.log("✅ Extracted User ID:", user_id);
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
            user_id,
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

        // 🔑 Extract Token from Authorization Header
        const token = req.headers.authorization?.split(" ")[1]; // "Bearer <token>"
        if (!token) {
            return res.status(401).json({ message: "Unauthorized: No token provided" });
        }

        // 🔓 Decode Token Without Verifying
        const decoded = jwt.decode(token);
        if (!decoded || !decoded.user_id) {
            return res.status(401).json({ message: "Unauthorized: Invalid token" });
        }

        const user_id = decoded.user_id;
        console.log("🔍 Fetching events for user:", user_id);

        // ✅ Filter events by user_id and department
        let { department } = req.query;
        let query = { user_id }; // Fetch only events created by the user

        if (department && department !== "All") {
            department = department.trim();
            query.clubDepartmentName = { $regex: new RegExp(`^${department}$`, "i") };
        }

        const events = await Event.find(query).select("eventName eventDate eventTime eventVenue organizer category description image status remarks");

        // 🔹 Include remarks ONLY if status is "Rejected" (2)
        const formattedEvents = events.map(event => ({
            ...event.toObject(),
            remarks: event.status === 2 ? event.remarks : undefined // Send remarks only for rejected events
        }));

        console.log(`✅ Sending ${formattedEvents.length} events (Remarks included for rejected)`);

        res.json(formattedEvents);
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

app.get("/api/ad_notices", async (req, res) => {
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
        const departmentMappings = {
            "Computer Science Department": "CSE",
            "Chemical Department": "CH",
            "Civil Department": "CE",
            "Electronics Department": "EEE",
            "Food Technology": "FT",
            "Mechanical Department": "ME"
        };

        const department = req.query.department;
        console.log(department) // Get department from frontend
        let query = { status: 1 }; // Only fetch approved events

        if (department) {
            const shortForm = departmentMappings[department];
            console.log(shortForm)
            if (shortForm) {
                query.clubDepartmentName = shortForm; // Filter by department short form
            } else {
                return res.status(400).json({ error: "Invalid department name" });
            }
        }
        
        const events = await Event.find(query);
        
        console.log(events)
        console.log("Generated Query:", query);

        // Transform data to match frontend format
        const mappedData = events.map(event => ({
            place: event.eventVenue,
            title: event.eventName.split(" ")[0] || "",
            title2: event.eventName.split(" ")[1] || "",
            description: event.description || "No description available.",
            image: event.image, // Assuming image is stored as Base64
        }));

        res.json(mappedData);
    } catch (error) {
        console.error("Error fetching events:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



// API to get event details by event_id
app.get("/api/events/:id", async (req, res) => {
    
    try {
        const event = await Event.findOne({ event_id: req.params.id });
        if (!event) {
            return res.status(404).json({ message: "Event not found" });
        }
        res.json(event);
    } catch (error) {
        console.error("Error fetching event:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});

app.get('/api/event-venue', async (req, res) => {
    const { blockId } = req.query;
    const today = new Date().toLocaleDateString('en-CA');
    console.log(today)
    console.log(`📩 Received request for blockId: ${blockId}`);

    if (!blockId) {
        console.log("❌ Missing blockId parameter");
        return res.status(400).json({ error: "Missing blockId parameter" });
    }

    try {
        console.log(`🔍 Fetching events for blockId: ${blockId} from collection: venue`);
        
        // Log exact database query
        const events = await EventVenue.find({ blockId: new RegExp(`^${blockId}$`, "i"),eventDate: today});

       
        
        if (events.length === 0) {
            console.log(`⚠️ No events found for blockId: ${blockId}`);
        } else {
            console.log(`✅ Found ${events.length} event(s) for blockId: ${blockId}`);
            console.log(events);
        }

        res.json(events);
    } catch (error) {
        console.error("🔥 Error fetching event venues:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



// Route to handle newsletter subscriptions
app.post("/subscribe", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: "Email is required!" });

        const existingUser = await News.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "You are already subscribed!" });

        await News.create({ email });
        res.json({ message: "Successfully subscribed!" });
    } catch (error) {
        res.status(500).json({ message: "Server error. Please try again." });
    }
});

async function syncVenues() {
    try {
        console.log("🔄 Syncing event venues...");

        // 🔹 Venue Mapping to Corresponding SVG `text id`
        const venueMap = {
            "RB": "block4",
            "AB BLOCK": "block1",
            "CLC": "block2",
            "AMPHITHEATRE": "block3",
            "NORTH BLOCK": "block5",
            "SOUTH BLOCK": "block6",
            "VB": "block7",
            "AMENITY": "block8",
            "MINI AUDITORIUM": "block9",
            "AK BLOCK": "block10",
            "LAB1": "block11",
            "LAB2": "block12",
            "LAB3": "block13",
            "LAB4": "block14"
        };

        // 🔹 Fetch only approved events (status: 1)
        const approvedEvents = await Event.find({ status: 1 });

        if (approvedEvents.length === 0) {
            console.log("ℹ️ No approved events found.");
            return;
        }

        // 🔹 Remove previous venue data to avoid duplicates
        await EventVenue.deleteMany({});

        // 🔹 Map eventVenue to corresponding `text id`
        const venueData = approvedEvents.map(event => {
            let blockId = "unknown"; // Default if no match is found
            const venueName = event.eventVenue.toUpperCase(); // Convert to uppercase for case-insensitive matching

            // Check if any keyword from venueMap is present in the venueName
            for (const [key, id] of Object.entries(venueMap)) {
                if (venueName.includes(key.toUpperCase())) {  // Check if venue contains the keyword
                    blockId = id;  // Assign corresponding `text id`
                    break;  // Stop searching after first match
                }
            }

            return {
                blockId: blockId, // Mapped to SVG `text id`
                eventName: event.eventName,
                eventTime: event.eventTime,
                venue: event.eventVenue,
                eventDate:event.eventDate
            };
        });

        // 🔹 Insert updated event venue data
        await EventVenue.insertMany(venueData);
        console.log(`✅ Synced ${venueData.length} venues.`);
    } catch (error) {
        console.error("❌ Error syncing venues:", error);
    }
}
// Function to Send Daily Event Emails
const sendDailyEventEmails = async () => {
    try {
        const today = new Date().toISOString().split("T")[0]; // Get today's date in YYYY-MM-DD format

        // Fetch only today's approved (status: 1) events
        const events = await Event.find({ eventDate: today, status: 1 }, "eventName eventTime eventVenue");

        if (events.length === 0) {
            console.log("No approved events scheduled for today.");
            return;
        }

        // Fetch all user emails from `news` collection
        const users = await News.find({}, "email");

        if (users.length === 0) {
            console.log("No users found to send emails.");
            return;
        }

        // Format event details
        const eventDetails = events.map(event => `
            <p><strong>${event.eventName}</strong></p>
            <p>⏰ Time: ${event.eventTime}</p>
            <p>📍 Venue: ${event.eventVenue}</p>
            <hr>
        `).join("");

        // Email Content
        const message = `
            <h2>Today's Scheduled Events</h2>
            ${eventDetails}
            <p>Stay updated with the latest events!</p>
        `;

        // Send Email to All Users
        for (let user of users) {
            await transporter.sendMail({
                from: `"Event Updates" <${process.env.SMTP_EMAIL}>`,
                to: user.email,
                subject: "Today's Events Update",
                html: message
            });
        }

        console.log("Daily event update emails sent successfully.");
    } catch (error) {
        console.error("Error sending daily event emails:", error);
    }
};

// Schedule Job to Run Every Day at 8 AM
cron.schedule("0 6 * * *", () => {
    console.log("Running daily event email job...");
    sendDailyEventEmails();
}, {
    timezone: "Asia/Kolkata" // Adjust timezone as needed
});

app.get("/test-send-email", async (req, res) => {
    try {
        await sendDailyEventEmails();
        res.json({ message: "Test email sent successfully!" });
    } catch (error) {
        res.status(500).json({ message: "Error sending test email." });
    }
});

// 🔹 API to get events happening today
/*
app.get('/api/events/today', async (req, res) => {
    console.log("fetch today venue")
    try {
        
        const today = new Date().toISOString().split('T')[0]; // Format YYYY-MM-DD

        // Fetch only approved events (status: 1) happening today
        const todayEvents = await Event.find({
            status: 1,
            eventDate: today
        });

        if (todayEvents.length === 0) {
            return res.json({ success: true, events: [] });
        }

        // Fetch corresponding block IDs from EventVenue
        const eventBlocks = todayEvents.map(event => ({
            blockId: event.blockId || "unknown",
            eventName: event.eventName,
            eventTime: event.eventTime
        }));

        res.json({ success: true, events: eventBlocks });
    } catch (error) {
        console.error("❌ Error fetching today's events:", error);
        res.status(500).json({ success: false, error: "Server Error" });
    }
});
*/


// ✅ Start Server
app.listen(5004, () => console.log("🚀 Server running on http://localhost:5004"));
