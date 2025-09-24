// server.js – Enhanced CourseMaker with Interactive Learning Features
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { exec } = require("child_process");
const multer = require("multer");
const textToSpeech = require("@google-cloud/text-to-speech");
const cookieParser = require("cookie-parser");

// Import our enhanced authentication and database utilities
const { 
  Database, 
  AuthManager, 
  CourseManager, 
  ProgressManager, 
  DiscussionManager, 
  AnalyticsManager, 
  GamificationManager 
} = require("./auth");

// --- Environment Configuration ---
const PORT = process.env.PORT || 80;
const MAX_FILE_SIZE = 200 * 1024 * 1024; // 200MB
const CLEANUP_DAYS = 7; // Delete files older than 7 days

// --- Paths ---
const ROOT = __dirname;
const UPLOADS = path.join(ROOT, "uploads");
const SLIDES_ROOT = path.join(ROOT, "slides");
const AUDIO_ROOT = path.join(ROOT, "generated_audio");
const INTERACTIVE_UPLOADS = path.join(ROOT, "interactive_uploads");

// Create directories
for (const p of [UPLOADS, SLIDES_ROOT, AUDIO_ROOT, INTERACTIVE_UPLOADS]) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

// --- Initialize Database and Managers ---
const database = new Database();
const authManager = new AuthManager(database);
const courseManager = new CourseManager(database);
const progressManager = new ProgressManager(database);
const discussionManager = new DiscussionManager(database);
const analyticsManager = new AnalyticsManager(database);
const gamificationManager = new GamificationManager(database);

// --- Google TTS client ---
const ttsClient = new textToSpeech.TextToSpeechClient({
  keyFilename: path.join(__dirname, "google-cloud-key.json"),
});

const app = express();
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: "4mb" }));
app.use(cookieParser());

// --- Authentication Middleware ---
async function requireAuth(req, res, next) {
  try {
    const sessionId = req.cookies.session_id;
    const session = await authManager.validateSession(sessionId);
    
    if (!session) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    
    req.user = session;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ success: false, error: 'Authentication failed' });
  }
}

// --- Static files ---
app.use(express.static(ROOT)); // Serve HTML files from root directory
app.use("/audio", express.static(AUDIO_ROOT));
app.use("/slides", express.static(SLIDES_ROOT));
app.use("/interactive", express.static(INTERACTIVE_UPLOADS));
const GOFORMS_ROOT = path.join(ROOT, "goforms");
app.use("/goforms", express.static(GOFORMS_ROOT));


// Serve different pages based on authentication
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/dashboard.html", (req, res) => res.sendFile(path.join(__dirname, "dashboard.html")));
app.get("/courses.html", (req, res) => res.sendFile(path.join(__dirname, "courses.html")));
app.get("/usage.html", (req, res) => res.sendFile(path.join(__dirname, "usage.html")));
app.get("/account.html", (req, res) => res.sendFile(path.join(__dirname, "account.html")));
app.get("/upgrade.html", (req, res) => res.sendFile(path.join(__dirname, "upgrade.html")));
app.get("/course-builder.html", (req, res) => res.sendFile(path.join(__dirname, "course-builder.html")));
app.get("/hotspot-builder.html", (req, res) => res.sendFile(path.join(__dirname, "hotspot-builder.html")));
app.get("/quiz-builder.html", (req, res) => res.sendFile(path.join(__dirname, "quiz-builder.html")));
app.get("/standardslides.html", (req, res) => res.sendFile(path.join(__dirname, "standardslides.html")));
app.get("/drag-and-drop-builder.html", (req, res) => res.sendFile(path.join(__dirname, "drag-drop-builder.html")));
app.get("/ai-course-builder.html", (req, res) => res.sendFile(path.join(__dirname, "ai-course-builder.html")));
app.get("/aibuilder.html", (req, res) => res.sendFile(path.join(__dirname, "aibuilder.html")));

// Serve interactive placeholder images
app.get("/interactive/placeholder.svg", (req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.sendFile(path.join(__dirname, "interactive", "placeholder.svg"));
});

// --- Usage tracking (enhanced with database storage) ---
const usageTracker = new Map();
const RATE_LIMIT = {
  slides: 50,    // Max slides per IP per hour
  audio: 100,    // Max audio generations per IP per hour
  window: 60 * 60 * 1000 // 1 hour
};

function trackUsage(ip, type) {
  const key = `${ip}-${type}`;
  const now = Date.now();
  
  if (!usageTracker.has(key)) {
    usageTracker.set(key, { count: 0, resetTime: now + RATE_LIMIT.window });
  }
  
  const usage = usageTracker.get(key);
  
  // Reset if window expired
  if (now > usage.resetTime) {
    usage.count = 0;
    usage.resetTime = now + RATE_LIMIT.window;
  }
  
  usage.count++;
  return usage.count <= RATE_LIMIT[type];
}

// --- TTS Caching System ---
function generateCacheKey(text, voice, speakingRate = 1.0) {
  const content = `${text}-${voice}-${speakingRate}`;
  return crypto.createHash('md5').update(content).digest('hex');
}

function getCachedAudio(cacheKey) {
  const audioFile = path.join(AUDIO_ROOT, `cached_${cacheKey}.mp3`);
  return fs.existsSync(audioFile) ? `/audio/cached_${cacheKey}.mp3` : null;
}

function saveToCache(cacheKey, audioContent) {
  const audioFile = path.join(AUDIO_ROOT, `cached_${cacheKey}.mp3`);
  fs.writeFileSync(audioFile, audioContent, "binary");
  return `/audio/cached_${cacheKey}.mp3`;
}

// --- File Cleanup Jobs ---
async function cleanupOldFiles() {
  const cutoff = Date.now() - (CLEANUP_DAYS * 24 * 60 * 60 * 1000);
  
  try {
    // Cleanup uploads
    const uploads = await fsp.readdir(UPLOADS);
    for (const file of uploads) {
      const filePath = path.join(UPLOADS, file);
      const stats = await fsp.stat(filePath);
      if (stats.mtime.getTime() < cutoff) {
        await fsp.unlink(filePath);
        console.log(`Cleaned up old upload: ${file}`);
      }
    }
    
    // Cleanup old slides (but keep recent projects)
    const slidesDirs = await fsp.readdir(SLIDES_ROOT);
    for (const dir of slidesDirs) {
      const dirPath = path.join(SLIDES_ROOT, dir);
      const stats = await fsp.stat(dirPath);
      if (stats.mtime.getTime() < cutoff) {
        await fsp.rm(dirPath, { recursive: true });
        console.log(`Cleaned up old slides: ${dir}`);
      }
    }
    
    // Cleanup old audio (keep cached files longer)
    const audioFiles = await fsp.readdir(AUDIO_ROOT);
    for (const file of audioFiles) {
      if (!file.startsWith('cached_')) { // Don't delete cached files
        const filePath = path.join(AUDIO_ROOT, file);
        const stats = await fsp.stat(filePath);
        if (stats.mtime.getTime() < cutoff) {
          await fsp.unlink(filePath);
          console.log(`Cleaned up old audio: ${file}`);
        }
      }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}

// Run cleanup every 6 hours
setInterval(cleanupOldFiles, 6 * 60 * 60 * 1000);

// --- AUTHENTICATION ROUTES ---

// Check authentication status
app.get("/api/auth/check", async (req, res) => {
  try {
    const sessionId = req.cookies.session_id;
    const session = await authManager.validateSession(sessionId);
    
    if (session) {
      res.json({ 
        authenticated: true, 
        user: {
          id: session.userId,
          email: session.email,
          name: session.name,
          planType: session.planType
        }
      });
    } else {
      res.status(401).json({ authenticated: false });
    }
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(500).json({ authenticated: false, error: 'Server error' });
  }
});

// User registration
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name, planType } = req.body;
    
    // Validate input
    if (!email || !password || !name) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email, password, and name are required' 
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ 
        success: false, 
        error: 'Password must be at least 8 characters long' 
      });
    }
    
    // Register user
    const result = await authManager.registerUser(email, password, name, planType || 'free');
    
    // Auto-login after registration
    const loginResult = await authManager.loginUser(email, password);
    
    // Set session cookie
    res.cookie('session_id', loginResult.sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.json({
      success: true,
      user: loginResult.user
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ 
      success: false, 
      error: error.message || 'Registration failed' 
    });
  }
});

// User login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and password are required' 
      });
    }
    
    const result = await authManager.loginUser(email, password);
    
    // Set session cookie
    res.cookie('session_id', result.sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    
    res.json({
      success: true,
      user: result.user
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ 
      success: false, 
      error: error.message || 'Login failed' 
    });
  }
});

// User logout
app.post("/api/auth/logout", async (req, res) => {
  try {
    const sessionId = req.cookies.session_id;
    if (sessionId) {
      await authManager.logoutUser(sessionId);
    }
    
    res.clearCookie('session_id');
    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

// --- USER PROFILE AND DASHBOARD ROUTES ---

// Get user profile
app.get("/api/user/profile", requireAuth, async (req, res) => {
  try {
    const user = await authManager.getUserWithLimits(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      planType: user.plan_type,
      limits: {
        max_courses: user.max_courses,
        max_slides_per_course: user.max_slides_per_course,
        max_characters_per_month: user.max_characters_per_month,
        max_interactive_slides: user.max_interactive_slides,
        max_students_per_course: user.max_students_per_course
      },
      available_features: user.available_features
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ success: false, error: 'Failed to load profile' });
  }
});

// Update user profile
app.put("/api/user/profile", requireAuth, async (req, res) => {
  try {
    const { name, bio } = req.body;
    
    await database.run(
      'UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [name, req.user.userId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ success: false, error: 'Failed to update profile' });
  }
});

// Change password
app.post("/api/user/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Get current user
    const user = await database.get('SELECT password_hash FROM users WHERE id = ?', [req.user.userId]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    // Verify current password
    const isValid = await authManager.verifyPassword(currentPassword, user.password_hash);
    if (!isValid) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }
    
    // Hash new password
    const newPasswordHash = await authManager.hashPassword(newPassword);
    
    // Update password
    await database.run(
      'UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newPasswordHash, req.user.userId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ success: false, error: 'Failed to change password' });
  }
});

// Update user preferences
app.put("/api/user/preferences", requireAuth, async (req, res) => {
  try {
    const preferences = req.body;
    
    // Store preferences in user record (you might want a separate preferences table)
    await database.run(
      'UPDATE users SET plan_features = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [JSON.stringify({ preferences }), req.user.userId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Preferences update error:', error);
    res.status(500).json({ success: false, error: 'Failed to update preferences' });
  }
});

// Delete user account
app.delete("/api/user/account", requireAuth, async (req, res) => {
  try {
    // Delete user data (courses, slides, etc. will cascade)
    await database.run('DELETE FROM users WHERE id = ?', [req.user.userId]);
    
    // Clear session
    res.clearCookie('session_id');
    res.json({ success: true });
  } catch (error) {
    console.error('Account deletion error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete account' });
  }
});

// Get user's courses
app.get("/api/user/courses", requireAuth, async (req, res) => {
  try {
    const courses = await courseManager.getUserCourses(req.user.userId);
    res.json(courses);
  } catch (error) {
    console.error('Get courses error:', error);
    res.status(500).json({ success: false, error: 'Failed to load courses' });
  }
});

// Get user's usage stats
app.get("/api/user/usage", requireAuth, async (req, res) => {
  try {
    const currentMonth = new Date().toISOString().substring(0, 7);
    const usage = await database.get(
      'SELECT * FROM usage_stats WHERE user_id = ? AND month = ?',
      [req.user.userId, currentMonth]
    );
    
    res.json(usage || {
      slides_created: 0,
      characters_used: 0,
      courses_created: 0,
      interactive_slides_created: 0,
      students_enrolled: 0,
      certificates_issued: 0
    });
  } catch (error) {
    console.error('Usage stats error:', error);
    res.status(500).json({ success: false, error: 'Failed to load usage stats' });
  }
});

// Get usage history
app.get("/api/user/usage-history", requireAuth, async (req, res) => {
  try {
    const history = await database.all(
      'SELECT * FROM usage_stats WHERE user_id = ? ORDER BY month DESC LIMIT 12',
      [req.user.userId]
    );
    res.json(history);
  } catch (error) {
    console.error('Usage history error:', error);
    res.status(500).json({ success: false, error: 'Failed to load usage history' });
  }
});

// Change plan endpoint  
app.post("/api/user/change-plan", requireAuth, async (req, res) => {
  try {
    const { newPlan, billing } = req.body;
    
    // Validate plan
    if (!['free', 'pro', 'business'].includes(newPlan)) {
      return res.status(400).json({ success: false, error: 'Invalid plan type' });
    }
    
    // For now, just update the plan directly (in production, you'd integrate with Stripe)
    await database.run(
      'UPDATE users SET plan_type = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [newPlan, req.user.userId]
    );
    
    // In a real implementation, you'd:
    // 1. Create Stripe checkout session for paid plans
    // 2. Return payment URL for client redirect
    // 3. Handle webhooks to confirm payment
    
    if (newPlan !== 'free') {
      res.json({ 
        success: true, 
        requiresPayment: true,
        paymentUrl: '/upgrade.html?checkout=true' // Mock payment URL
      });
    } else {
      res.json({ success: true, requiresPayment: false });
    }
  } catch (error) {
    console.error('Plan change error:', error);
    res.status(500).json({ success: false, error: 'Failed to change plan' });
  }
});

// --- COURSE MANAGEMENT ROUTES ---

// Create new course
const storage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, UPLOADS);
  },
  filename: function (_req, file, cb) {
    const id = uuidv4();
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `ppt_${id}${ext || ".pptx"}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ];
    const allowedExts = ['.ppt', '.pptx'];
    const ext = path.extname(file.originalname || "").toLowerCase();
    
    if (allowedMimes.includes(file.mimetype) || allowedExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only PowerPoint files (.ppt, .pptx) are allowed.'));
    }
  }
});

app.post("/api/user/create-course", requireAuth, upload.single("ppt"), async (req, res) => {
  const tempPpt = req.file?.path;
  if (!tempPpt) return res.status(400).json({ success: false, error: "No PowerPoint file uploaded." });

  try {
    // Check plan limits
    const canCreateCourse = await authManager.checkPlanLimits(req.user.userId, 'create_course');
    if (!canCreateCourse.allowed) {
      // Clean up uploaded file
      try { await fsp.unlink(tempPpt); } catch {}
      return res.status(403).json({ success: false, error: canCreateCourse.reason });
    }

    const { title, description } = req.body;
    if (!title) {
      try { await fsp.unlink(tempPpt); } catch {}
      return res.status(400).json({ success: false, error: "Course title is required." });
    }

    // Create course record
    const course = await courseManager.createCourse(req.user.userId, title, description);
    
    const jobId = uuidv4();
    const jobDir = path.join(SLIDES_ROOT, jobId);
    await fsp.mkdir(jobDir, { recursive: true });

    const pdfDir = path.dirname(tempPpt);
    const baseName = path.basename(tempPpt, path.extname(tempPpt));
    const pdfPath = path.join(pdfDir, `${baseName}.pdf`);

    // Convert PPT to PDF
    try {
      await run(`soffice --headless --convert-to pdf --outdir "${pdfDir}" "${tempPpt}"`);
    } catch (err) {
      console.error("LibreOffice conversion error:", err);
      let errorMsg = "PowerPoint conversion failed.";
      if (err.stderr?.includes("password")) {
        errorMsg = "Password-protected presentations are not supported.";
      } else if (err.stderr?.includes("corrupt")) {
        errorMsg = "The presentation file appears to be corrupted.";
      }
      throw new Error(errorMsg);
    }

    if (!fs.existsSync(pdfPath)) {
      throw new Error("PDF conversion failed. Please check your PowerPoint file.");
    }

    // Convert PDF to PNGs
    const tmpPngPrefix = path.join(pdfDir, `${baseName}_slide`);
    try {
      await run(`pdftoppm -png -rx 180 -ry 180 "${pdfPath}" "${tmpPngPrefix}"`);
    } catch (err) {
      console.error("PDF to PNG conversion error:", err);
      throw new Error("Slide image generation failed.");
    }

    const files = (await fsp.readdir(pdfDir)).filter(f => f.startsWith(`${baseName}_slide`) && f.endsWith(".png")).sort();
    if (!files.length) {
      throw new Error("No slides found in presentation. Please check your PowerPoint file.");
    }

    // Check slide count limit
    const canAddSlides = await authManager.checkPlanLimits(req.user.userId, 'add_slides', { slideCount: files.length });
    if (!canAddSlides.allowed) {
      throw new Error(canAddSlides.reason);
    }

    // Move slides to project directory
    let idx = 1;
    const urls = [];
    for (const f of files) {
      const src = path.join(pdfDir, f);
      const name = `slide-${String(idx).padStart(3, "0")}.png`;
      const dest = path.join(jobDir, name);
      await fsp.rename(src, dest);
      urls.push(`/slides/${jobId}/${name}`);
      idx++;
    }

    // Add slides to course
    await courseManager.addSlidesToCourse(course.id, urls, jobId);

    // Update usage stats
    await authManager.updateUsage(req.user.userId, 'courses', 1);
    await authManager.updateUsage(req.user.userId, 'slides', files.length);

    // Award gamification points and check badges
    await gamificationManager.awardPoints(req.user.userId, 50, 'Created a course');
    await gamificationManager.checkAutomaticBadges(req.user.userId, 'course_created');

    // Cleanup temporary files
    try { await fsp.unlink(tempPpt); } catch {}
    try { await fsp.unlink(pdfPath); } catch {}

    console.log(`Successfully created course: ${files.length} slides for user ${req.user.userId}`);

    return res.json({ 
      success: true, 
      course: course,
      jobId, 
      count: urls.length, 
      slides: urls,
      message: `Successfully created course with ${urls.length} slide(s)`
    });
    
  } catch (err) {
    console.error("Course creation error:", err?.message || err);
    
    // Cleanup on error
    try { await fsp.unlink(tempPpt); } catch {}
    
    return res.status(500).json({ 
      success: false, 
      error: err.message || "Course creation failed." 
    });
  }
});

// Get specific course data for course builder
app.get("/api/user/course/:courseId", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    res.json(course);
  } catch (error) {
    console.error('Get course error:', error);
    res.status(500).json({ success: false, error: 'Failed to load course' });
  }
});

// Get course slides (augmented with interactive data for hotspot slides)
app.get("/api/user/course/:courseId/slides", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Base slides
    const slides = await database.all(
      'SELECT * FROM slides WHERE course_id = ? ORDER BY slide_number',
      [courseId]
    );

    // Parse interactive_data + attach interactive data for different slide types
    for (const s of slides) {
      try { s.interactive_data = JSON.parse(s.interactive_data || '{}'); } catch { s.interactive_data = {}; }

      if (s.slide_type === 'hotspot') {
        const hotspots = await database.all(
          'SELECT id, x_position, y_position, title, description, icon_type, audio_url FROM slide_hotspots WHERE slide_id = ? ORDER BY id',
          [s.id]
        );
        s.hotspots = hotspots; // <- player can render these
      } else if (s.slide_type === 'quiz' || s.slide_type === 'assessment') {
        const questions = await database.all(
          'SELECT id, question_text, question_type, correct_answer, options, explanation, points_value FROM quiz_questions WHERE slide_id = ? ORDER BY id',
          [s.id]
        );
        s.questions = questions; // <- player can render these
      }
    }

    res.json(slides);
  } catch (error) {
    console.error('Get slides error:', error);
    res.status(500).json({ success: false, error: 'Failed to load slides' });
  }
});


// Update slide narration
app.post("/api/user/course/:courseId/slide/:slideNumber/narration", requireAuth, async (req, res) => {
  try {
    const { courseId, slideNumber } = req.params;
    const { narration_text, audio_url, voice_settings } = req.body;
    
    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    // Update slide narration
    await database.run(`
      UPDATE slides 
      SET narration_text = ?, audio_url = ?, voice_settings = ?, updated_at = CURRENT_TIMESTAMP
      WHERE course_id = ? AND slide_number = ?
    `, [narration_text, audio_url, JSON.stringify(voice_settings), courseId, slideNumber]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update narration error:', error);
    res.status(500).json({ success: false, error: 'Failed to update narration' });
  }
});

// Publish course
app.post("/api/user/course/:courseId/publish", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    // Update course status
    await database.run(`
      UPDATE courses 
      SET status = 'published', is_public = 1, published_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [courseId]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Publish course error:', error);
    res.status(500).json({ success: false, error: 'Failed to publish course' });
  }
});

// Duplicate course
app.post("/api/user/course/:courseId/duplicate", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    // Check plan limits
    const canCreateCourse = await authManager.checkPlanLimits(req.user.userId, 'create_course');
    if (!canCreateCourse.allowed) {
      return res.status(403).json({ success: false, error: canCreateCourse.reason });
    }
    
    // Create duplicate course
    const newCourse = await courseManager.createCourse(
      req.user.userId, 
      `${course.title} (Copy)`, 
      course.description
    );
    
    // Copy slides
    const slides = await database.all(
      'SELECT * FROM slides WHERE course_id = ? ORDER BY slide_number',
      [courseId]
    );
    
    for (const slide of slides) {
      await database.run(`
        INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, audio_url, narration_text, voice_settings, interactive_data, points_value)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [newCourse.id, slide.slide_number, slide.slide_type, slide.title, slide.content, slide.image_url, slide.audio_url, slide.narration_text, slide.voice_settings, slide.interactive_data, slide.points_value]);
    }
    
    // Update course slide count
    await database.run(`
      UPDATE courses SET slide_count = ? WHERE id = ?
    `, [slides.length, newCourse.id]);
    
    // Update usage stats
    await authManager.updateUsage(req.user.userId, 'courses', 1);
    
    res.json({ success: true, course: newCourse });
  } catch (error) {
    console.error('Duplicate course error:', error);
    res.status(500).json({ success: false, error: 'Failed to duplicate course' });
  }
});

// Delete course
app.delete("/api/user/course/:courseId", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    
    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    // Delete course (slides will cascade)
    await database.run('DELETE FROM courses WHERE id = ?', [courseId]);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete course error:', error);
    res.status(500).json({ success: false, error: 'Failed to delete course' });
  }
});

// --- AI COURSE GENERATION ROUTES ---

// Test course generation endpoint
app.get("/api/ai/test-course", async (req, res) => {
  try {
    const mockCourse = generateMockCourseStructure({
      topic: 'Test Course',
      audience: 'Beginners',
      slideCount: 3,
      style: 'professional'
    });
    
    res.json({
      success: true,
      course: mockCourse
    });
  } catch (error) {
    console.error('Test course error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Test course generation failed',
      details: error.message 
    });
  }
});

// Test ChatGPT API endpoint
app.get("/api/ai/test-chatgpt", async (req, res) => {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer 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',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-3.5-turbo',
        messages: [
          {
            role: 'user',
            content: 'Say "Hello, ChatGPT is working!" and return only that text.'
          }
        ],
        max_tokens: 50
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(500).json({ 
        success: false, 
        error: `ChatGPT API error: ${response.status}`,
        details: errorText
      });
    }

    const data = await response.json();
    res.json({ 
      success: true, 
      message: 'ChatGPT API is working',
      response: data.choices[0].message.content
    });

  } catch (error) {
    console.error('ChatGPT test error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'ChatGPT API test failed',
      details: error.message 
    });
  }
});

// Advanced AI course generation with ChatGPT + Google TTS
app.post("/api/ai/generate-course-advanced", requireAuth, async (req, res) => {
  try {
    const { topic, audience, slideCount, style } = req.body;
    
    // Validate input
    if (!topic || !audience) {
      return res.status(400).json({ 
        success: false, 
        error: 'Course topic and audience are required' 
      });
    }

    // Check plan limits
    const canCreateCourse = await authManager.checkPlanLimits(req.user.userId, 'create_course');
    if (!canCreateCourse.allowed) {
      return res.status(403).json({ success: false, error: canCreateCourse.reason });
    }

    // Generate course structure using ChatGPT
    const courseStructure = await generateAdvancedCourseStructure({
      topic,
      audience,
      slideCount: slideCount || 5,
      style: style || 'professional'
    });

    // Create course record
    const course = await courseManager.createCourse(
      req.user.userId, 
      courseStructure.title, 
      courseStructure.description
    );

    // Generate slides with content, audio, and timing
    const slides = await generateAdvancedCourseSlides(course.id, courseStructure, {
      voice: 'en-US-Neural2-A'
    });

    // Update course with slide count
    await database.run(
      'UPDATE courses SET slide_count = ? WHERE id = ?',
      [slides.length, course.id]
    );

    // Update usage stats
    await authManager.updateUsage(req.user.userId, 'courses', 1);
    await authManager.updateUsage(req.user.userId, 'slides', slides.length);

    // Award gamification points
    await gamificationManager.awardPoints(req.user.userId, 150, 'Created advanced AI course');
    await gamificationManager.checkAutomaticBadges(req.user.userId, 'ai_course_created');

    res.json({
      success: true,
      course: {
        id: course.id,
        title: courseStructure.title,
        description: courseStructure.description,
        slides: slides,
        estimatedDuration: courseStructure.estimatedDuration,
        difficulty: courseStructure.difficulty
      }
    });

  } catch (error) {
    console.error('Advanced AI course generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to generate advanced AI course',
      details: error.message 
    });
  }
});

// Generate AI course
app.post("/api/ai/generate-course", requireAuth, async (req, res) => {
  try {
    const { topic, audience, duration, objectives, interactive, voice } = req.body;
    
    // Validate input
    if (!topic || !audience) {
      return res.status(400).json({ 
        success: false, 
        error: 'Course topic and audience are required' 
      });
    }

    // Check plan limits
    const canCreateCourse = await authManager.checkPlanLimits(req.user.userId, 'create_course');
    if (!canCreateCourse.allowed) {
      return res.status(403).json({ success: false, error: canCreateCourse.reason });
    }

    // Generate course structure using AI
    const courseStructure = await generateCourseStructure({
      topic,
      audience,
      duration,
      objectives,
      interactive: interactive || []
    });

    // Create course record
    const course = await courseManager.createCourse(
      req.user.userId, 
      courseStructure.title, 
      courseStructure.description
    );

    // Generate slides with content and audio
    const slides = await generateCourseSlides(course.id, courseStructure, {
      voice: voice || 'en-US-Neural2-A',
      interactive: interactive || []
    });

    // Update course with slide count
    await database.run(
      'UPDATE courses SET slide_count = ? WHERE id = ?',
      [slides.length, course.id]
    );

    // Update usage stats
    await authManager.updateUsage(req.user.userId, 'courses', 1);
    await authManager.updateUsage(req.user.userId, 'slides', slides.length);
    await authManager.updateUsage(req.user.userId, 'interactive_slides', slides.filter(s => s.slide_type !== 'standard').length);

    // Award gamification points
    await gamificationManager.awardPoints(req.user.userId, 100, 'Created AI course');
    await gamificationManager.checkAutomaticBadges(req.user.userId, 'ai_course_created');

    res.json({
      success: true,
      course: {
        id: course.id,
        title: courseStructure.title,
        description: courseStructure.description,
        slides: slides,
        estimatedDuration: courseStructure.estimatedDuration,
        difficulty: courseStructure.difficulty
      }
    });

  } catch (error) {
    console.error('AI course generation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to generate AI course',
      details: error.message 
    });
  }
});

// Advanced course structure generation with ChatGPT
async function generateAdvancedCourseStructure(params) {
  const { topic, audience, slideCount, style } = params;
  
  try {
    // Call ChatGPT API to generate course structure
    const chatGPTResponse = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer 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',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: `You are an expert course designer. Create a professional course structure with ${slideCount} slides about "${topic}" for "${audience}" in a ${style} style. 

CRITICAL REQUIREMENTS:
1. Each slide MUST have a unique, relevant image URL from Pexels
2. SSML must include <mark> tags for each element that should appear
3. Timepoints should be realistic timing for when each element appears
4. Use different layouts: HeroLeft, TwoCol, Checklist, ProcessTimeline, ImageFocus

Return ONLY a valid JSON object with this exact structure:
{
  "title": "Course Title",
  "description": "Brief course description", 
  "estimatedDuration": 120,
  "difficulty": "Beginner",
  "slides": [
    {
      "id": "s1",
      "layout": "HeroLeft",
      "durationSec": 15,
      "theme": {"primary": "#008080", "accent": "#333333", "bg": "#f8fafc"},
      "elements": [
        {"id": "h1", "type": "heading", "text": "Slide Title", "motion": "rise"},
        {"id": "sub1", "type": "subheading", "text": "Subtitle", "motion": "fade"},
        {"id": "img1", "type": "image", "url": "https://images.pexels.com/photos/UNIQUE_ID/pexels-photo-UNIQUE_ID.jpeg", "caption": "Relevant caption", "motion": "pop"}
      ],
      "audio": {
        "ssml": "<speak>Welcome! <mark name='h1'/> Today you'll learn about <mark name='sub1'/> key concepts. <mark name='img1'/> This image shows what we're discussing.</speak>",
        "voice": "en-US-Neural2-A"
      },
      "marks": [
        {"name": "h1", "targetId": "h1"},
        {"name": "sub1", "targetId": "sub1"},
        {"name": "img1", "targetId": "img1"}
      ],
      "timepoints": [0.8, 3.0, 5.5]
    }
  ]
}

IMPORTANT: 
- Use REAL Pexels image URLs (replace UNIQUE_ID with actual photo IDs)
- Each slide needs different, relevant images
- SSML must sync with visual reveals
- Return ONLY the JSON object, no other text or formatting.`
          },
          {
            role: 'user',
            content: `Create a ${slideCount}-slide course about "${topic}" for "${audience}" in a ${style} style.`
          }
        ],
        temperature: 0.7,
        max_tokens: 4000
      })
    });

    if (!chatGPTResponse.ok) {
      const errorText = await chatGPTResponse.text();
      console.error('ChatGPT API error:', chatGPTResponse.status, errorText);
      throw new Error(`ChatGPT API call failed: ${chatGPTResponse.status} - ${errorText}`);
    }

    const chatGPTData = await chatGPTResponse.json();
    
    if (!chatGPTData.choices || !chatGPTData.choices[0] || !chatGPTData.choices[0].message) {
      console.error('Invalid ChatGPT response structure:', chatGPTData);
      throw new Error('Invalid response from ChatGPT API');
    }
    
    const content = chatGPTData.choices[0].message.content;
    console.log('ChatGPT response content:', content);
    
    // Clean the content to extract JSON
    let jsonContent = content.trim();
    
    // Remove any markdown formatting
    if (jsonContent.startsWith('```json')) {
      jsonContent = jsonContent.replace(/^```json\s*/, '').replace(/\s*```$/, '');
    } else if (jsonContent.startsWith('```')) {
      jsonContent = jsonContent.replace(/^```\s*/, '').replace(/\s*```$/, '');
    }
    
    // Parse the JSON response
    const courseStructure = JSON.parse(jsonContent);
    
    return courseStructure;
    
  } catch (error) {
    console.error('ChatGPT generation error:', error);
    console.log('Falling back to mock course structure...');
    
    // Fallback to mock data if ChatGPT fails
    return generateMockCourseStructure(params);
  }
}

// Generate advanced course slides with ChatGPT + TTS
async function generateAdvancedCourseSlides(courseId, courseStructure, options) {
  const slides = [];
  
  for (const slideData of courseStructure.slides) {
    try {
      // Create slide record
      const slideResult = await database.run(`
        INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, interactive_data, points_value, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `, [
        courseId,
        slideData.id,
        'ai_generated',
        slideData.elements.find(e => e.type === 'heading')?.text || 'AI Generated Slide',
        JSON.stringify(slideData),
        slideData.elements.find(e => e.type === 'image')?.url || 'https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg',
        JSON.stringify(slideData),
        10
      ]);

      const slideId = slideResult.lastID;

      // Generate audio using Google TTS with SSML
      let audioUrl = null;
      if (slideData.audio && slideData.audio.ssml) {
        try {
          const audioResponse = await generateSSMLAudio(slideData.audio.ssml, slideData.audio.voice || 'en-US-Neural2-A');
          if (audioResponse.success) {
            audioUrl = audioResponse.audioUrl;
            await database.run(
              'UPDATE slides SET audio_url = ?, narration_text = ? WHERE id = ?',
              [audioUrl, slideData.audio.ssml, slideId]
            );
            console.log('Generated audio for slide', slideId, ':', audioUrl);
          }
        } catch (audioError) {
          console.error('Audio generation error for slide', slideId, audioError);
        }
      }

      slides.push({
        id: slideId,
        slideNumber: slideData.id,
        slideType: 'ai_generated',
        title: slideData.elements.find(e => e.type === 'heading')?.text || 'AI Generated Slide',
        content: slideData,
        hasAudio: !!audioUrl,
        audioUrl: audioUrl,
        layout: slideData.layout,
        durationSec: slideData.durationSec,
        theme: slideData.theme,
        elements: slideData.elements,
        marks: slideData.marks,
        timepoints: slideData.timepoints,
        // Add proper image URL
        imageUrl: slideData.elements.find(e => e.type === 'image')?.url || 'https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg'
      });

    } catch (error) {
      console.error('Error creating advanced slide:', error);
    }
  }

  return slides;
}

// Generate SSML audio with Google TTS
async function generateSSMLAudio(ssml, voice) {
  try {
    const clean = String(ssml || "").slice(0, 5000);
    if (!clean) return { success: false, error: "No SSML provided" };

    const languageCode = inferLanguageCode(voice || "en-US-Neural2-A");
    const finalRate = 1.0;

    // Check cache first
    const cacheKey = generateCacheKey(clean, voice, finalRate);
    const cachedUrl = getCachedAudio(cacheKey);
    
    if (cachedUrl) {
      return {
        success: true,
        cached: true,
        audioUrl: cachedUrl
      };
    }

    // Build TTS request with SSML
    const voiceParams = { languageCode };
    const selected = ALLOWED_NEURAL2.includes(voice) ? voice : "en-US-Neural2-A";
    voiceParams.name = selected;

    const audioConfig = { 
      audioEncoding: "MP3",
      speakingRate: finalRate
    };

    const request = {
      input: { ssml: clean }, // Use SSML instead of text
      voice: voiceParams,
      audioConfig: audioConfig,
    };

    const [response] = await ttsClient.synthesizeSpeech(request);
    if (!response || !response.audioContent) {
      throw new Error("No audio content returned by Google TTS.");
    }

    // Save to cache
    const audioUrl = saveToCache(cacheKey, response.audioContent);

    return {
      success: true,
      cached: false,
      audioUrl: audioUrl
    };

  } catch (error) {
    console.error('SSML TTS generation error:', error);
    return { success: false, error: error.message };
  }
}

// Mock course structure fallback
function generateMockCourseStructure(params) {
  const { topic, audience, slideCount, style } = params;
  
  const courseStructure = {
    title: `${topic} - Complete Guide`,
    description: `A comprehensive course on ${topic} designed for ${audience}.`,
    estimatedDuration: slideCount * 15, // 15 seconds per slide
    difficulty: 'Beginner',
    slides: []
  };

  // Generate slide structure
  for (let i = 1; i <= slideCount; i++) {
    let layout = 'HeroLeft';
    let elements = [];
    let marks = [];
    let timepoints = [];
    let ssml = '';
    
    if (i === 1) {
      layout = 'HeroLeft';
      elements = [
        { id: "h1", type: "heading", text: `Welcome to ${topic}`, motion: "rise" },
        { id: "sub1", type: "subheading", text: `Perfect for ${audience}`, motion: "fade" },
        { id: "img1", type: "image", url: "https://images.pexels.com/photos/1181675/pexels-photo-1181675.jpeg", caption: "Learning made easy", motion: "pop" }
      ];
      marks = [
        { name: "h1", targetId: "h1" },
        { name: "sub1", targetId: "sub1" }
      ];
      timepoints = [0.8, 3.0];
      ssml = `<speak>Welcome to our course on ${topic}! <mark name='h1'/> This course is perfect for ${audience}. <mark name='sub1'/> Let's get started!</speak>`;
    } else if (i === slideCount) {
      layout = 'ImageFocus';
      elements = [
        { id: "h5", type: "heading", text: "Course Complete!", motion: "rise" },
        { id: "call1", type: "callout", title: "Next Steps:", body: "Apply what you've learned and continue your journey!", motion: "pop" }
      ];
      marks = [
        { name: "h5", targetId: "h5" },
        { name: "call1", targetId: "call1" }
      ];
      timepoints = [0.8, 4.0];
      ssml = `<speak>Congratulations! <mark name='h5'/> You've completed the course on ${topic}. <mark name='call1'/> Now it's time to apply what you've learned!</speak>`;
    } else if (i === 2) {
      layout = 'TwoCol';
      elements = [
        { id: "h2", type: "heading", text: `What is ${topic}?`, motion: "rise" },
        { id: "b1", type: "bullets", items: [`Definition and basics`, `Why it matters`, `Real-world applications`], motion: "fade" },
        { id: "img2", type: "image", url: "https://images.pexels.com/photos/1181244/pexels-photo-1181244.jpeg", caption: "Understanding the concept", motion: "pop" }
      ];
      marks = [
        { name: "h2", targetId: "h2" },
        { name: "b1_1", targetId: "b1", index: 0 },
        { name: "b1_2", targetId: "b1", index: 1 },
        { name: "b1_3", targetId: "b1", index: 2 },
        { name: "img2", targetId: "img2" }
      ];
      timepoints = [0.8, 3.0, 6.0, 9.0, 12.0];
      ssml = `<speak>Let's start with the basics. <mark name='h2'/> What exactly is ${topic}? <mark name='b1_1'/> First, let's define it clearly. <mark name='b1_2'/> Second, understand why it matters. <mark name='b1_3'/> Finally, see how it applies in the real world. <mark name='img2'/> This image illustrates the concept perfectly.</speak>`;
    } else if (i === 3) {
      layout = 'ProcessTimeline';
      elements = [
        { id: "h3", type: "heading", text: "Step-by-Step Process", motion: "rise" },
        { id: "tl1", type: "timeline", items: [
          { label: "Step 1", summary: "Get started with the basics" },
          { label: "Step 2", summary: "Build your foundation" },
          { label: "Step 3", summary: "Apply your knowledge" }
        ], motion: "fade" },
        { id: "img3", type: "image", url: "https://images.pexels.com/photos/1181263/pexels-photo-1181263.jpeg", caption: "Step-by-step process", motion: "pop" }
      ];
      marks = [
        { name: "h3", targetId: "h3" },
        { name: "tl1_1", targetId: "tl1", index: 0 },
        { name: "tl1_2", targetId: "tl1", index: 1 },
        { name: "tl1_3", targetId: "tl1", index: 2 },
        { name: "img3", targetId: "img3" }
      ];
      timepoints = [0.8, 3.0, 6.0, 9.0, 12.0];
      ssml = `<speak>Now let's walk through the process. <mark name='h3'/> Here's how to approach ${topic} step by step. <mark name='tl1_1'/> First, get started with the basics. <mark name='tl1_2'/> Then, build your foundation. <mark name='tl1_3'/> Finally, apply your knowledge. <mark name='img3'/> This visual guide shows the complete process.</speak>`;
    } else {
      layout = 'TwoCol';
      elements = [
        { id: "h2", type: "heading", text: `Lesson ${i - 1}: ${topic} Fundamentals`, motion: "rise" },
        { id: "b1", type: "bullets", items: [`Key concept ${i - 1}`, `Important point ${i - 1}`, `Practical application ${i - 1}`], motion: "fade" }
      ];
      marks = [
        { name: "h2", targetId: "h2" },
        { name: "b1_1", targetId: "b1", index: 0 },
        { name: "b1_2", targetId: "b1", index: 1 },
        { name: "b1_3", targetId: "b1", index: 2 }
      ];
      timepoints = [0.8, 3.0, 6.0, 9.0];
      ssml = `<speak>Welcome to lesson ${i - 1}. <mark name='h2'/> Let's explore the key concepts. <mark name='b1_1'/> First point, <mark name='b1_2'/> second point, <mark name='b1_3'/> and third point.</speak>`;
    }

    courseStructure.slides.push({
      id: `s${i}`,
      layout: layout,
      durationSec: 15,
      theme: { primary: "#008080", accent: "#333333", bg: "#f8fafc" },
      elements: elements,
      audio: {
        ssml: ssml,
        voice: "en-US-Neural2-A"
      },
      marks: marks,
      timepoints: timepoints
    });
  }

  return courseStructure;
}

// Generate course structure using AI
async function generateCourseStructure(params) {
  // This is a mock implementation - in production, you'd use OpenAI API
  const { topic, audience, duration, objectives, interactive } = params;
  
  // Determine slide count based on duration
  const slideCounts = {
    short: 8,
    medium: 15,
    long: 25,
    comprehensive: 35
  };
  
  const slideCount = slideCounts[duration] || 15;
  
  // Generate course structure
  const courseStructure = {
    title: `${topic} - Complete Guide`,
    description: `A comprehensive course on ${topic} designed for ${audience}. ${objectives ? `Learning objectives: ${objectives}` : ''}`,
    estimatedDuration: Math.ceil(slideCount * 1.5), // 1.5 minutes per slide
    difficulty: 'Beginner',
    slides: []
  };

  // Generate slide structure
  for (let i = 1; i <= slideCount; i++) {
    let slideType = 'standard';
    let title = '';
    let content = '';
    
    // Determine slide type and content based on position and interactive preferences
    if (i === 1) {
      title = 'Welcome and Introduction';
      content = `Welcome to our comprehensive course on ${topic}. In this course, you'll learn everything you need to know about ${topic} from the ground up.`;
    } else if (i === slideCount) {
      title = 'Course Conclusion and Next Steps';
      content = `Congratulations! You've completed the course on ${topic}. You now have a solid foundation and are ready to apply what you've learned.`;
    } else if (i % 5 === 0 && interactive.includes('quiz')) {
      slideType = 'quiz';
      title = `Knowledge Check: ${topic} Fundamentals`;
      content = `Let's test your understanding of the key concepts we've covered so far.`;
    } else if (i % 7 === 0 && interactive.includes('hotspot')) {
      slideType = 'hotspot';
      title = `Interactive Exploration: ${topic} in Practice`;
      content = `Click on the different areas to explore real-world applications and examples.`;
    } else if (i % 9 === 0 && interactive.includes('timeline')) {
      slideType = 'timeline';
      title = `Timeline: Evolution of ${topic}`;
      content = `Explore the key milestones and developments in the field of ${topic}.`;
    } else {
      title = `Lesson ${i - 1}: ${topic} Fundamentals`;
      content = `In this lesson, we'll dive deeper into the core concepts of ${topic}. You'll learn practical techniques and best practices that you can apply immediately.`;
    }

    courseStructure.slides.push({
      slideNumber: i,
      slideType: slideType,
      title: title,
      content: content,
      hasAudio: true,
      audioTiming: generateAudioTiming(content)
    });
  }

  return courseStructure;
}

// Generate course slides with content and audio
async function generateCourseSlides(courseId, courseStructure, options) {
  const slides = [];
  
  for (const slideData of courseStructure.slides) {
    try {
      // Create slide record
      const slideResult = await database.run(`
        INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, interactive_data, points_value, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      `, [
        courseId,
        slideData.slideNumber,
        slideData.slideType,
        slideData.title,
        slideData.content,
        '/images/placeholder-slide.png',
        JSON.stringify({}),
        slideData.slideType === 'quiz' ? 20 : 10
      ]);

      const slideId = slideResult.lastID;

      // Generate audio if needed
      if (slideData.hasAudio) {
        try {
          const audioResponse = await generateSlideAudio(slideData.content, options.voice);
          if (audioResponse.success) {
            await database.run(
              'UPDATE slides SET audio_url = ?, narration_text = ? WHERE id = ?',
              [audioResponse.audioUrl, slideData.content, slideId]
            );
          }
        } catch (audioError) {
          console.error('Audio generation error for slide', slideId, audioError);
        }
      }

      // Create interactive elements based on slide type
      if (slideData.slideType === 'quiz') {
        await createQuizQuestions(slideId, slideData.content);
      } else if (slideData.slideType === 'hotspot') {
        await createHotspotElements(slideId, slideData.content);
      } else if (slideData.slideType === 'timeline') {
        await createTimelineEvents(slideId, slideData.content);
      }

      slides.push({
        id: slideId,
        slideNumber: slideData.slideNumber,
        slideType: slideData.slideType,
        title: slideData.title,
        content: slideData.content,
        hasAudio: slideData.hasAudio,
        audioUrl: slideData.hasAudio ? '/audio/generated-audio.mp3' : null
      });

    } catch (error) {
      console.error('Error creating slide:', error);
    }
  }

  return slides;
}

// Generate audio for slide content
async function generateSlideAudio(content, voice) {
  try {
    // Use the existing TTS generation logic directly
    const clean = String(content || "").slice(0, 5000);
    if (!clean) return { success: false, error: "No text provided" };

    const isChirp = typeof voice === "string" && voice.startsWith("Chirp3-HD:");
    const languageCode = inferLanguageCode(voice || "en-US-Neural2-A");
    const finalRate = 1.0;

    // Check cache first
    const cacheKey = generateCacheKey(clean, voice, finalRate);
    const cachedUrl = getCachedAudio(cacheKey);
    
    if (cachedUrl) {
      return {
        success: true,
        cached: true,
        audioUrl: cachedUrl
      };
    }

    // Build TTS request
    const voiceParams = { languageCode };
    if (isChirp) {
      const [, loc, name] = voice.split(":");
      voiceParams.name = `${loc}-Chirp3-HD-${name}`;
    } else {
      const selected = ALLOWED_NEURAL2.includes(voice) ? voice : "en-US-Neural2-A";
      voiceParams.name = selected;
    }

    const audioConfig = { audioEncoding: "MP3" };
    if (finalRate !== 1.0) {
      audioConfig.speakingRate = finalRate;
    }

    const request = {
      input: { text: clean },
      voice: voiceParams,
      audioConfig: audioConfig,
    };

    const [response] = await ttsClient.synthesizeSpeech(request);
    if (!response || !response.audioContent) {
      throw new Error("No audio content returned by Google TTS.");
    }

    // Save to cache
    const audioUrl = saveToCache(cacheKey, response.audioContent);

    return {
      success: true,
      cached: false,
      audioUrl: audioUrl
    };

  } catch (error) {
    console.error('TTS generation error:', error);
    return { success: false, error: error.message };
  }
}

// Generate audio timing for content
function generateAudioTiming(content) {
  // Estimate timing based on content length (roughly 150 words per minute)
  const wordCount = content.split(' ').length;
  const estimatedDuration = Math.ceil((wordCount / 150) * 60); // in seconds
  
  return {
    duration: estimatedDuration,
    segments: [
      { start: 0, end: estimatedDuration, text: content }
    ]
  };
}

// Create quiz questions for quiz slides
async function createQuizQuestions(slideId, content) {
  const questions = [
    {
      question_text: `What is the main topic discussed in this lesson?`,
      question_type: 'multiple_choice',
      correct_answer: JSON.stringify([0]),
      options: JSON.stringify([
        'Basic concepts',
        'Advanced techniques', 
        'Historical background',
        'Future trends'
      ]),
      explanation: 'This lesson covers the fundamental concepts that form the foundation of the topic.',
      points_value: 5
    }
  ];

  for (const question of questions) {
    await database.run(`
      INSERT INTO quiz_questions (slide_id, question_text, question_type, correct_answer, options, explanation, points_value)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      slideId,
      question.question_text,
      question.question_type,
      question.correct_answer,
      question.options,
      question.explanation,
      question.points_value
    ]);
  }
}

// Create hotspot elements for hotspot slides
async function createHotspotElements(slideId, content) {
  const hotspots = [
    {
      x_position: 200,
      y_position: 150,
      title: 'Key Concept 1',
      description: 'Click to learn more about this important concept.',
      icon_type: 'info',
      audio_url: null
    },
    {
      x_position: 400,
      y_position: 200,
      title: 'Example',
      description: 'See a real-world example of this concept in action.',
      icon_type: 'example',
      audio_url: null
    },
    {
      x_position: 300,
      y_position: 300,
      title: 'Practice',
      description: 'Try applying what you\'ve learned.',
      icon_type: 'practice',
      audio_url: null
    }
  ];

  for (const hotspot of hotspots) {
    await database.run(`
      INSERT INTO slide_hotspots (slide_id, x_position, y_position, title, description, icon_type, audio_url)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      slideId,
      hotspot.x_position,
      hotspot.y_position,
      hotspot.title,
      hotspot.description,
      hotspot.icon_type,
      hotspot.audio_url
    ]);
  }
}

// Create timeline events for timeline slides
async function createTimelineEvents(slideId, content) {
  const events = [
    {
      event_order: 1,
      title: 'Early Development',
      description: 'The initial concepts and foundations were established.',
      date: '1990s',
      image_url: null
    },
    {
      event_order: 2,
      title: 'Major Breakthrough',
      description: 'A significant advancement that changed the field.',
      date: '2000s',
      image_url: null
    },
    {
      event_order: 3,
      title: 'Modern Era',
      description: 'Current state and recent developments.',
      date: '2010s-Present',
      image_url: null
    }
  ];

  for (const event of events) {
    await database.run(`
      INSERT INTO timeline_events (slide_id, event_order, title, description, date, image_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [
      slideId,
      event.event_order,
      event.title,
      event.description,
      event.date,
      event.image_url
    ]);
  }
}

// --- INTERACTIVE SLIDE ROUTES ---

// Interactive file upload for hotspots, etc.
const interactiveStorage = multer.diskStorage({
  destination: function (_req, _file, cb) {
    cb(null, INTERACTIVE_UPLOADS);
  },
  filename: function (_req, file, cb) {
    const id = uuidv4();
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `interactive_${id}${ext}`);
  },
});

const interactiveUpload = multer({
  storage: interactiveStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB for images/videos
  fileFilter: (req, file, cb) => {
    const allowedMimes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/webm', 'video/ogg'
    ];
    
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only image and video files are allowed.'));
    }
  }
});

// Upload file for interactive content
app.post("/api/user/upload-interactive", requireAuth, interactiveUpload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "No file uploaded" });
    }

    const fileUrl = `/interactive/${req.file.filename}`;
    
    // Store file record in database
    await database.run(`
      INSERT INTO file_uploads (user_id, filename, original_filename, file_path, file_size, file_type, upload_type)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      req.user.userId,
      req.file.filename,
      req.file.originalname,
      req.file.path,
      req.file.size,
      req.file.mimetype,
      'interactive_content'
    ]);

    res.json({ 
      success: true, 
      fileUrl,
      filename: req.file.filename,
      originalName: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype
    });
  } catch (error) {
    console.error('Interactive upload error:', error);
    res.status(500).json({ success: false, error: 'Failed to upload file' });
  }
});

// Create interactive slide
app.post("/api/user/course/:courseId/interactive-slide", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { slideType, data } = req.body;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Check plan limits for interactive slides
    const canCreateInteractive = await authManager.checkPlanLimits(req.user.userId, 'create_interactive_slide');
    if (!canCreateInteractive.allowed) {
      return res.status(403).json({ success: false, error: canCreateInteractive.reason });
    }

    // Create the interactive slide
    const result = await courseManager.createInteractiveSlide(courseId, slideType, data);

    // Update usage stats
    await authManager.updateUsage(req.user.userId, 'interactive_slides', 1);

    // Award points and check badges
    await gamificationManager.awardPoints(req.user.userId, 25, `Created ${slideType} slide`);
    await gamificationManager.checkAutomaticBadges(req.user.userId, 'interactive_slide_created');

    res.json({ 
      success: true, 
      slideId: result.slideId,
      slideNumber: result.slideNumber,
      message: `${slideType} slide created successfully`
    });
  } catch (error) {
    console.error('Create interactive slide error:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      courseId: req.params.courseId,
      slideType: req.body.slideType,
      data: req.body.data
    });
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create interactive slide',
      details: error.message 
    });
  }
});

// Get interactive slide data
app.get("/api/user/course/:courseId/slide/:slideId/interactive", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.params;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get slide data
    const slide = await database.get(
      'SELECT * FROM slides WHERE id = ? AND course_id = ?',
      [slideId, courseId]
    );

    if (!slide) {
      return res.status(404).json({ success: false, error: 'Slide not found' });
    }

    let interactiveData = {};

    // Get type-specific data
    switch (slide.slide_type) {
      case 'hotspot':
        const hotspots = await database.all(
          'SELECT * FROM slide_hotspots WHERE slide_id = ? ORDER BY id',
          [slideId]
        );
        interactiveData.hotspots = hotspots;
        break;

      case 'quiz':
      case 'assessment':
        const questions = await database.all(
          'SELECT * FROM quiz_questions WHERE slide_id = ? ORDER BY id',
          [slideId]
        );
        questions.forEach(q => {
          q.correct_answer = JSON.parse(q.correct_answer || '[]');
          q.options = JSON.parse(q.options || '[]');
        });
        interactiveData.questions = questions;
        break;

      case 'drag_drop':
        const items = await database.all(
          'SELECT * FROM drag_drop_items WHERE slide_id = ? ORDER BY id',
          [slideId]
        );
        interactiveData.items = items;
        break;

      case 'timeline':
        const events = await database.all(
          'SELECT * FROM timeline_events WHERE slide_id = ? ORDER BY event_order',
          [slideId]
        );
        interactiveData.events = events;
        break;

      case 'before_after':
        const comparison = await database.get(
          'SELECT * FROM before_after_content WHERE slide_id = ?',
          [slideId]
        );
        interactiveData.comparison = comparison;
        break;
    }

    res.json({ 
      success: true, 
      slide: {
        ...slide,
        interactive_data: JSON.parse(slide.interactive_data || '{}'),
        ...interactiveData
      }
    });
  } catch (error) {
    console.error('Get interactive slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to load interactive slide' });
  }
});

// Update interactive slide
app.put("/api/user/course/:courseId/slide/:slideId/interactive", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.params;
    const { data } = req.body;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get slide
    const slide = await database.get(
      'SELECT * FROM slides WHERE id = ? AND course_id = ?',
      [slideId, courseId]
    );

    if (!slide) {
      return res.status(404).json({ success: false, error: 'Slide not found' });
    }

    // Update slide
    await database.run(`
      UPDATE slides 
      SET title = ?, content = ?, interactive_data = ?, points_value = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `, [
      data.title || slide.title,
      data.content || slide.content,
      JSON.stringify(data.interactiveData || {}),
      data.pointsValue || slide.points_value,
      slideId
    ]);

    // Update type-specific data based on slide type
    switch (slide.slide_type) {
      case 'hotspot':
        if (data.hotspots) {
          // Delete existing hotspots
          await database.run('DELETE FROM slide_hotspots WHERE slide_id = ?', [slideId]);
          
          // Insert new hotspots
          for (const hotspot of data.hotspots) {
            await database.run(`
              INSERT INTO slide_hotspots (slide_id, x_position, y_position, title, description, icon_type, audio_url)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [slideId, hotspot.x, hotspot.y, hotspot.title, hotspot.description, hotspot.icon || 'info', hotspot.audioUrl]);
          }
        }
        break;

      case 'quiz':
      case 'assessment':
        if (data.questions) {
          // Delete existing questions
          await database.run('DELETE FROM quiz_questions WHERE slide_id = ?', [slideId]);
          
          // Insert new questions
          for (const question of data.questions) {
            await database.run(`
              INSERT INTO quiz_questions (slide_id, question_text, question_type, correct_answer, options, explanation, points_value)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
              slideId,
              question.text,
              question.type || 'multiple_choice',
              JSON.stringify(question.correctAnswer),
              JSON.stringify(question.options || []),
              question.explanation || '',
              question.points || 1
            ]);
          }
        }
        break;

      // Add other slide types as needed...
    }

    res.json({ success: true, message: 'Interactive slide updated successfully' });
  } catch (error) {
    console.error('Update interactive slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to update interactive slide' });
  }
});

// --- STANDARD SLIDE ROUTES ---

// Save standard slide
app.post("/api/save-standard-slide", requireAuth, async (req, res) => {
  try {
    const { courseId, slideIndex, slideData } = req.body;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get the slide
    let slide = await database.get(
      'SELECT * FROM slides WHERE course_id = ? AND slide_number = ?',
      [courseId, parseInt(slideIndex) + 1]
    );

    if (!slide) {
      // Create the slide if it doesn't exist
      const result = await database.run(
        'INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, interactive_data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
        [courseId, parseInt(slideIndex) + 1, 'standard', `Slide ${parseInt(slideIndex) + 1}`, '', '/images/placeholder-slide.png', JSON.stringify(slideData)]
      );
      slide = { id: result.lastID };
    } else {
      // Update the existing slide with standard slide data
      await database.run(
        'UPDATE slides SET slide_type = ?, interactive_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        ['standard', JSON.stringify(slideData), slide.id]
      );
    }

    res.json({ success: true, message: 'Standard slide saved successfully' });
  } catch (error) {
    console.error('Save standard slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to save standard slide' });
  }
});

// Load standard slide
app.get("/api/load-standard-slide", requireAuth, async (req, res) => {
  try {
    const { courseId, slideIndex } = req.query;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get the slide
    const slide = await database.get(
      'SELECT * FROM slides WHERE course_id = ? AND slide_number = ?',
      [courseId, parseInt(slideIndex) + 1]
    );

    if (!slide) {
      return res.status(404).json({ success: false, error: 'Slide not found' });
    }

    let slideData = {};
    try {
      slideData = JSON.parse(slide.interactive_data || '{}');
    } catch (e) {
      slideData = {};
    }

    res.json({ success: true, slideData });
  } catch (error) {
    console.error('Load standard slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to load standard slide' });
  }
});

// Save drag and drop slide
app.post("/api/save-drag-drop-slide", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId, slideData } = req.body;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    if (slideId) {
      // Update existing slide
      await database.run(
        'UPDATE slides SET slide_type = ?, title = ?, content = ?, interactive_data = ?, points_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND course_id = ?',
        ['drag_drop', slideData.title, slideData.instructions, JSON.stringify(slideData), slideData.points || 10, slideId, courseId]
      );
    } else {
      // Create new slide
      const slideNumber = await database.get(
        'SELECT MAX(slide_number) as max_num FROM slides WHERE course_id = ?',
        [courseId]
      );
      const nextSlideNumber = (slideNumber.max_num || 0) + 1;

      await database.run(
        'INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, interactive_data, points_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
        [courseId, nextSlideNumber, 'drag_drop', slideData.title, slideData.instructions, '/images/placeholder-slide.png', JSON.stringify(slideData), slideData.points || 10]
      );
    }

    res.json({ success: true, message: 'Drag & drop slide saved successfully' });
  } catch (error) {
    console.error('Save drag drop slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to save drag & drop slide' });
  }
});

// Load drag and drop slide
app.get("/api/load-drag-drop-slide", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.query;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get the slide
    const slide = await database.get(
      'SELECT * FROM slides WHERE id = ? AND course_id = ?',
      [slideId, courseId]
    );

    if (!slide) {
      return res.status(404).json({ success: false, error: 'Slide not found' });
    }

    res.json({ 
      success: true, 
      slide: {
        ...slide,
        interactive_data: slide.interactive_data ? JSON.parse(slide.interactive_data) : null
      }
    });
  } catch (error) {
    console.error('Load drag drop slide error:', error);
    res.status(500).json({ success: false, error: 'Failed to load drag & drop slide' });
  }
});

// --- STUDENT PROGRESS ROUTES ---

// Enroll in a course
app.post("/api/course/:courseId/enroll", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;

    // Check if course exists and is published
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND status = "published"',
      [courseId]
    );

    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found or not published' });
    }

    // Check if already enrolled
    const existing = await database.get(
      'SELECT * FROM course_enrollments WHERE user_id = ? AND course_id = ?',
      [req.user.userId, courseId]
    );

    if (existing) {
      return res.json({ success: true, message: 'Already enrolled', enrollment: existing });
    }

    // Create enrollment
    await database.run(`
      INSERT INTO course_enrollments (user_id, course_id, status, enrolled_at)
      VALUES (?, ?, 'enrolled', CURRENT_TIMESTAMP)
    `, [req.user.userId, courseId]);

    // Track analytics
    await analyticsManager.trackCourseView(courseId, req.user.userId, null, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.cookies.session_id
    });

    res.json({ success: true, message: 'Successfully enrolled in course' });
  } catch (error) {
    console.error('Course enrollment error:', error);
    res.status(500).json({ success: false, error: 'Failed to enroll in course' });
  }
});

// Update slide progress
app.post("/api/course/:courseId/slide/:slideId/progress", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.params;
    const { completed, score, timeSpent, interactionsCount } = req.body;

    // Update progress
    const result = await progressManager.updateSlideProgress(
      req.user.userId,
      courseId,
      slideId,
      { completed, score, timeSpent, interactionsCount }
    );

    // Award points if slide completed
    if (completed) {
      const slide = await database.get('SELECT points_value FROM slides WHERE id = ?', [slideId]);
      const points = slide?.points_value || 10; // Default 10 points per slide
      await gamificationManager.awardPoints(req.user.userId, points, 'Completed slide');
    }

    res.json({ success: true, progress: result });
  } catch (error) {
    console.error('Update progress error:', error);
    res.status(500).json({ success: false, error: 'Failed to update progress' });
  }
});

// Get course progress
app.get("/api/course/:courseId/progress", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    const progress = await progressManager.getCourseProgress(req.user.userId, courseId);
    res.json({ success: true, progress });
  } catch (error) {
    console.error('Get progress error:', error);
    res.status(500).json({ success: false, error: 'Failed to load progress' });
  }
});

// --- DISCUSSION ROUTES ---

// Get course discussions
app.get("/api/course/:courseId/discussions", async (req, res) => {
  try {
    const { courseId } = req.params;
    const { slideId } = req.query;
    
    const discussions = await discussionManager.getDiscussions(
      courseId, 
      slideId || null,
      50, // limit
      0   // offset
    );
    
    res.json({ success: true, discussions });
  } catch (error) {
    console.error('Get discussions error:', error);
    res.status(500).json({ success: false, error: 'Failed to load discussions' });
  }
});

// Create discussion post
app.post("/api/course/:courseId/discussions", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { content, slideId, parentId } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ success: false, error: 'Content is required' });
    }

    const result = await discussionManager.createPost(
      courseId,
      req.user.userId,
      content.trim(),
      slideId || null,
      parentId || null
    );

    res.json({ success: true, postId: result.postId });
  } catch (error) {
    console.error('Create discussion error:', error);
    res.status(500).json({ success: false, error: 'Failed to create discussion post' });
  }
});

// --- ANALYTICS ROUTES ---

// Get course analytics (for course owners)
app.get("/api/user/course/:courseId/analytics", requireAuth, async (req, res) => {
  try {
    const { courseId } = req.params;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    const analytics = await analyticsManager.getCourseAnalytics(courseId);
    res.json({ success: true, analytics });
  } catch (error) {
    console.error('Get analytics error:', error);
    res.status(500).json({ success: false, error: 'Failed to load analytics' });
  }
});

// --- GAMIFICATION ROUTES ---

// Get user gamification data
app.get("/api/user/gamification", requireAuth, async (req, res) => {
  try {
    const data = await gamificationManager.getUserGamification(req.user.userId);
    res.json({ success: true, gamification: data });
  } catch (error) {
    console.error('Get gamification error:', error);
    res.status(500).json({ success: false, error: 'Failed to load gamification data' });
  }
});

// Get leaderboard
app.get("/api/leaderboard", async (req, res) => {
  try {
    const leaderboard = await database.all(`
      SELECT 
        u.id,
        u.name,
        u.total_points,
        u.level,
        COUNT(c.id) as courses_created
      FROM users u
      LEFT JOIN courses c ON u.id = c.user_id
      WHERE u.id > 0 AND u.is_active = 1
      GROUP BY u.id
      ORDER BY u.total_points DESC, u.level DESC
      LIMIT 50
    `);

    res.json({ success: true, leaderboard });
  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ success: false, error: 'Failed to load leaderboard' });
  }
});

// --- TTS with User Authentication and Limits ---
const ALLOWED_NEURAL2 = [
  "en-US-Neural2-A","en-US-Neural2-C","en-US-Neural2-D","en-US-Neural2-F",
  "en-GB-Neural2-A","en-GB-Neural2-B",
  "en-AU-Neural2-A","en-AU-Neural2-B",
];
const CHIRP3_PREFIX = "Chirp3-HD:";

function inferLanguageCode(voiceName) {
  if (voiceName.startsWith(CHIRP3_PREFIX)) {
    const parts = voiceName.split(":");
    return parts[1] || "en-US";
  }
  const parts = voiceName.split("-");
  return parts.length >= 2 ? `${parts[0]}-${parts[1]}` : "en-US";
}

app.post("/api/generate-tts", async (req, res) => {
  try {
    const { text, voice, speakingRate } = req.body || {};
    const clean = String(text || "").slice(0, 5000);
    if (!clean) return res.status(400).json({ success: false, error: "No text provided." });

    // Check if user is authenticated for plan limits
    let userId = null;
    const sessionId = req.cookies.session_id;
    if (sessionId) {
      const session = await authManager.validateSession(sessionId);
      if (session) {
        userId = session.userId;
        
        // Check character limits for authenticated users
        const canGenerate = await authManager.checkPlanLimits(userId, 'generate_audio', { characters: clean.length });
        if (!canGenerate.allowed) {
          return res.status(403).json({ success: false, error: canGenerate.reason });
        }
        
        // Check if user has access to requested voice type
        const isChirp = typeof voice === "string" && voice.startsWith(CHIRP3_PREFIX);
        const requiredFeature = isChirp ? 'chirp3_voices' : 'neural2_voices';
        
        if (requiredFeature === 'neural2_voices') {
          const hasFeature = await authManager.checkPlanLimits(userId, 'use_feature', { feature: requiredFeature });
          if (!hasFeature.allowed) {
            return res.status(403).json({ success: false, error: 'Neural2 voices require Pro plan or higher' });
          }
        } else if (requiredFeature === 'chirp3_voices') {
          const hasFeature = await authManager.checkPlanLimits(userId, 'use_feature', { feature: requiredFeature });
          if (!hasFeature.allowed) {
            return res.status(403).json({ success: false, error: 'Chirp3 HD voices require Business plan' });
          }
        }
      }
    }

    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    
    // Rate limiting for unauthenticated users
    if (!userId && !trackUsage(clientIP, 'audio')) {
      return res.status(429).json({ 
        success: false, 
        error: "Rate limit exceeded. Please sign in or try again later." 
      });
    }

    const isChirp = typeof voice === "string" && voice.startsWith(CHIRP3_PREFIX);
    const languageCode = inferLanguageCode(voice || "en-US-Neural2-A");
    const finalRate = typeof speakingRate === "number" ? Math.max(0.25, Math.min(2.0, speakingRate)) : 1.0;

    // Check cache first
    const cacheKey = generateCacheKey(clean, voice, finalRate);
    const cachedUrl = getCachedAudio(cacheKey);
    
    if (cachedUrl) {
      return res.json({
        success: true,
        cached: true,
        charactersUsed: clean.length,
        audioUrl: cachedUrl,
        model: isChirp ? "CHIRP3" : "NEURAL2",
        voice: voice,
        speakingRate: finalRate
      });
    }

    // Build TTS request
    const voiceParams = { languageCode };
    if (isChirp) {
      const [, loc, name] = voice.split(":");
      voiceParams.name = `${loc}-Chirp3-HD-${name}`;
    } else {
      const selected = ALLOWED_NEURAL2.includes(voice) ? voice : "en-US-Neural2-A";
      voiceParams.name = selected;
    }

    const audioConfig = { audioEncoding: "MP3" };
    if (finalRate !== 1.0) {
      audioConfig.speakingRate = finalRate;
    }

    const request = {
      input: { text: clean },
      voice: voiceParams,
      audioConfig: audioConfig,
    };

    const [response] = await ttsClient.synthesizeSpeech(request);
    if (!response || !response.audioContent) {
      throw new Error("No audio content returned by Google TTS.");
    }

    // Save to cache
    const audioUrl = saveToCache(cacheKey, response.audioContent);

    // Update usage stats for authenticated users
    if (userId) {
      await authManager.updateUsage(userId, 'characters', clean.length);
      await gamificationManager.checkAutomaticBadges(userId, 'tts_generated');
    }

    res.json({
      success: true,
      cached: false,
      charactersUsed: clean.length,
      audioUrl: audioUrl,
      model: isChirp ? "CHIRP3" : "NEURAL2",
      voice: voiceParams.name,
      speakingRate: finalRate
    });
  } catch (err) {
    console.error("TTS error:", err?.message || err);
    
    // More specific error messages
    let errorMsg = "TTS generation failed.";
    if (err.message.includes("Invalid voice")) {
      errorMsg = "Selected voice is not available for this language.";
    } else if (err.message.includes("quota")) {
      errorMsg = "TTS quota exceeded. Please try again later.";
    } else if (err.message.includes("authentication")) {
      errorMsg = "TTS service temporarily unavailable.";
    }
    
    res.status(500).json({ success: false, error: errorMsg });
  }
});

// --- Legacy PPT Upload (for non-authenticated users) ---
app.post("/api/upload-ppt", upload.single("ppt"), async (req, res) => {
  const tempPpt = req.file?.path;
  if (!tempPpt) return res.status(400).json({ success: false, error: "No PowerPoint file uploaded." });

  const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Rate limiting for slide generation
  if (!trackUsage(clientIP, 'slides')) {
    try { await fsp.unlink(tempPpt); } catch {}
    return res.status(429).json({ 
      success: false, 
      error: "Upload limit exceeded. Please sign in or try again later." 
    });
  }

  const jobId = uuidv4();
  const jobDir = path.join(SLIDES_ROOT, jobId);
  
  try {
    await fsp.mkdir(jobDir, { recursive: true });

    const pdfDir = path.dirname(tempPpt);
    const baseName = path.basename(tempPpt, path.extname(tempPpt));
    const pdfPath = path.join(pdfDir, `${baseName}.pdf`);

    // Convert PPT to PDF with better error handling
    try {
      await run(`soffice --headless --convert-to pdf --outdir "${pdfDir}" "${tempPpt}"`);
    } catch (err) {
      console.error("LibreOffice conversion error:", err);
      
      let errorMsg = "PowerPoint conversion failed.";
      if (err.stderr?.includes("password")) {
        errorMsg = "Password-protected presentations are not supported.";
      } else if (err.stderr?.includes("corrupt")) {
        errorMsg = "The presentation file appears to be corrupted.";
      } else if (err.code === 'ENOENT') {
        errorMsg = "Conversion service temporarily unavailable.";
      }
      
      throw new Error(errorMsg);
    }

    if (!fs.existsSync(pdfPath)) {
      throw new Error("PDF conversion failed. Please check your PowerPoint file.");
    }

    // Convert PDF to PNGs
    const tmpPngPrefix = path.join(pdfDir, `${baseName}_slide`);
    try {
      await run(`pdftoppm -png -rx 180 -ry 180 "${pdfPath}" "${tmpPngPrefix}"`);
    } catch (err) {
      console.error("PDF to PNG conversion error:", err);
      throw new Error("Slide image generation failed.");
    }

    const files = (await fsp.readdir(pdfDir)).filter(f => f.startsWith(`${baseName}_slide`) && f.endsWith(".png")).sort();
    if (!files.length) {
      throw new Error("No slides found in presentation. Please check your PowerPoint file.");
    }

    // Move slides to project directory
    let idx = 1;
    const urls = [];
    for (const f of files) {
      const src = path.join(pdfDir, f);
      const name = `slide-${String(idx).padStart(3, "0")}.png`;
      const dest = path.join(jobDir, name);
      await fsp.rename(src, dest);
      urls.push(`/slides/${jobId}/${name}`);
      idx++;
    }

    // Cleanup temporary files immediately
    try { await fsp.unlink(tempPpt); } catch {}
    try { await fsp.unlink(pdfPath); } catch {}

    console.log(`Successfully converted PPT: ${files.length} slides generated for job ${jobId}`);

    return res.json({ 
      success: true, 
      jobId, 
      count: urls.length, 
      slides: urls,
      message: `Successfully converted ${urls.length} slide(s)`
    });
    
  } catch (err) {
    console.error("PPT conversion error:", err?.message || err);
    
    // Cleanup on error
    try { await fsp.unlink(tempPpt); } catch {}
    try { await fsp.rm(jobDir, { recursive: true }); } catch {}
    
    return res.status(500).json({ 
      success: false, 
      error: err.message || "PowerPoint conversion failed." 
    });
  }
});

// --- DRAG & DROP BUILDER API ROUTES ---

// Get drag & drop exercise data
app.get("/api/courses/:courseId/slides/:slideId/drag-drop", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.params;
    
    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Get slide data
    const slide = await database.get(
      'SELECT * FROM slides WHERE id = ? AND course_id = ?',
      [slideId, courseId]
    );

    if (!slide) {
      return res.status(404).json({ success: false, error: 'Slide not found' });
    }

    // Parse interactive data
    let exerciseData = {};
    try {
      exerciseData = JSON.parse(slide.interactive_data || '{}');
    } catch (e) {
      exerciseData = {};
    }

    res.json(exerciseData);
  } catch (error) {
    console.error('Get drag drop exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to load exercise' });
  }
});

// Save drag & drop exercise data
app.put("/api/courses/:courseId/slides/:slideId/drag-drop", requireAuth, async (req, res) => {
  try {
    const { courseId, slideId } = req.params;
    const exerciseData = req.body;

    // Verify user owns this course
    const course = await database.get(
      'SELECT * FROM courses WHERE id = ? AND user_id = ?',
      [courseId, req.user.userId]
    );
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }

    // Update slide with exercise data
    await database.run(
      'UPDATE slides SET interactive_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND course_id = ?',
      [JSON.stringify(exerciseData), slideId, courseId]
    );

    res.json({ success: true, message: 'Exercise saved successfully' });
  } catch (error) {
    console.error('Save drag drop exercise error:', error);
    res.status(500).json({ success: false, error: 'Failed to save exercise' });
  }
});

// --- PUBLIC COURSE ROUTES ---

// Get public course by slug
app.get("/api/course/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const course = await courseManager.getPublicCourse(slug);
    
    if (!course) {
      return res.status(404).json({ success: false, error: 'Course not found' });
    }
    
    // Track view
    await analyticsManager.trackCourseView(course.id, null, null, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.cookies.session_id
    });
    
    res.json(course);
  } catch (error) {
    console.error('Get public course error:', error);
    res.status(500).json({ success: false, error: 'Failed to load course' });
  }
});

// --- UTILITY FUNCTIONS ---
function run(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    exec(cmd, { timeout: 5 * 60 * 1000, maxBuffer: 1024 * 1024 * 256, ...opts }, (err, stdout, stderr) => {
      if (err) {
        const error = new Error(stderr || err.message);
        error.stdout = stdout;
        error.stderr = stderr;
        error.code = err.code;
        return reject(error);
      }
      resolve({ stdout, stderr });
    });
  });
}

// --- Health Check Endpoint ---
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "healthy", 
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
});

// --- Error handling middleware ---
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 200MB.'
      });
    }
  }
  
  console.error('Unhandled error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

app.listen(PORT, () => {
  console.log(`Enhanced CourseMaker with Interactive Features running on port ${PORT}`);
  console.log(`Database: SQLite`);
  console.log(`Cleanup job runs every 6 hours, deleting files older than ${CLEANUP_DAYS} days`);
});