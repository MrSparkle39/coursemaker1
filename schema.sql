-- CourseMaker SQLite Database Schema
-- Enhanced with Interactive Learning Features
-- Designed for easy tier adjustments and feature scaling

-- Users table (unchanged)
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  plan_type TEXT DEFAULT 'free' CHECK(plan_type IN ('free', 'pro', 'business')),
  plan_features TEXT DEFAULT '{}', -- JSON for flexible feature flags
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME,
  is_active BOOLEAN DEFAULT 1,
  stripe_customer_id TEXT, -- For future Stripe integration
  subscription_status TEXT DEFAULT 'active', -- active, cancelled, past_due, etc.
  total_points INTEGER DEFAULT 0, -- Gamification points
  level INTEGER DEFAULT 1 -- User level based on points
);

-- Courses table (unchanged)
CREATE TABLE courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  slug TEXT UNIQUE, -- For public URLs like /course/my-awesome-course
  thumbnail_url TEXT, -- First slide or custom thumbnail
  status TEXT DEFAULT 'draft' CHECK(status IN ('draft', 'published', 'archived')),
  slide_count INTEGER DEFAULT 0,
  total_duration INTEGER DEFAULT 0, -- Total audio duration in seconds
  is_public BOOLEAN DEFAULT 0, -- Whether course can be viewed without login
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  published_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Enhanced Slides table with interactive content support
CREATE TABLE slides (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL,
  slide_number INTEGER NOT NULL, -- 1, 2, 3, etc.
  slide_type TEXT DEFAULT 'standard' CHECK(slide_type IN ('standard', 'hotspot', 'quiz', 'assessment', 'video', 'drag_drop', 'timeline', 'before_after')),
  title TEXT,
  content TEXT, -- Additional text content for the slide
  image_url TEXT NOT NULL, -- /slides/job-id/slide-001.png
  audio_url TEXT, -- /audio/cached_hash.mp3 or null if no narration
  narration_text TEXT, -- The text used for TTS
  voice_settings TEXT DEFAULT '{}', -- JSON: {"voice": "en-US-Neural2-A", "rate": 1.0}
  duration INTEGER DEFAULT 0, -- Audio duration in seconds
  interactive_data TEXT DEFAULT '{}', -- JSON for interactive elements (hotspots, quiz questions, etc.)
  points_value INTEGER DEFAULT 0, -- Points awarded for completing this slide
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  UNIQUE(course_id, slide_number)
);

-- Hotspot-specific table for better querying and relationships
CREATE TABLE slide_hotspots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slide_id INTEGER NOT NULL,
  x_position REAL NOT NULL, -- X coordinate as percentage (0.0 to 1.0)
  y_position REAL NOT NULL, -- Y coordinate as percentage (0.0 to 1.0)
  title TEXT NOT NULL,
  description TEXT,
  icon_type TEXT DEFAULT 'info', -- info, warning, help, etc.
  audio_url TEXT, -- Optional TTS for this hotspot
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Quiz questions for quiz and assessment slides
CREATE TABLE quiz_questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slide_id INTEGER NOT NULL,
  question_text TEXT NOT NULL,
  question_type TEXT DEFAULT 'multiple_choice' CHECK(question_type IN ('multiple_choice', 'true_false', 'text_input', 'drag_drop')),
  correct_answer TEXT, -- JSON array for multiple choice, string for others
  options TEXT, -- JSON array of possible answers
  explanation TEXT, -- Explanation shown after answer
  points_value INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Drag and drop exercise items
CREATE TABLE drag_drop_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slide_id INTEGER NOT NULL,
  item_text TEXT NOT NULL,
  item_type TEXT DEFAULT 'draggable' CHECK(item_type IN ('draggable', 'drop_zone')),
  correct_match_id INTEGER, -- ID of the item this should match with
  x_position REAL, -- Starting position for draggables
  y_position REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Timeline events for timeline slides
CREATE TABLE timeline_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slide_id INTEGER NOT NULL,
  event_date TEXT, -- Date string or year
  event_title TEXT NOT NULL,
  event_description TEXT,
  event_order INTEGER, -- Order on timeline
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Before/After comparison content
CREATE TABLE before_after_content (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slide_id INTEGER NOT NULL,
  before_image_url TEXT NOT NULL,
  after_image_url TEXT NOT NULL,
  before_title TEXT,
  after_title TEXT,
  before_description TEXT,
  after_description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Student progress tracking
CREATE TABLE student_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  slide_id INTEGER NOT NULL,
  completed BOOLEAN DEFAULT 0,
  score REAL, -- Score for assessments (0.0 to 1.0)
  time_spent INTEGER DEFAULT 0, -- Time in seconds
  interactions_count INTEGER DEFAULT 0, -- Number of interactions
  completed_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE,
  UNIQUE(user_id, slide_id)
);

-- Course enrollments for student tracking
CREATE TABLE course_enrollments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  status TEXT DEFAULT 'enrolled' CHECK(status IN ('enrolled', 'in_progress', 'completed', 'dropped')),
  progress_percentage REAL DEFAULT 0.0,
  total_score REAL, -- Overall course score
  enrolled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME,
  certificate_url TEXT, -- URL to completion certificate
  certificate_issued_at DATETIME,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  UNIQUE(user_id, course_id)
);

-- Student notes and bookmarks
CREATE TABLE student_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  course_id INTEGER NOT NULL,
  slide_id INTEGER NOT NULL,
  note_text TEXT NOT NULL,
  note_type TEXT DEFAULT 'note' CHECK(note_type IN ('note', 'bookmark', 'question')),
  x_position REAL, -- For positioned notes
  y_position REAL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- Discussion system for courses
CREATE TABLE course_discussions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL,
  slide_id INTEGER, -- NULL for general course discussion
  user_id INTEGER NOT NULL,
  parent_id INTEGER, -- For threaded replies
  content TEXT NOT NULL,
  is_question BOOLEAN DEFAULT 0,
  is_answer BOOLEAN DEFAULT 0, -- Marked as answer by instructor
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_id) REFERENCES course_discussions(id) ON DELETE CASCADE
);

-- Gamification: Badges
CREATE TABLE badges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  icon_url TEXT,
  points_required INTEGER DEFAULT 0,
  rarity TEXT DEFAULT 'common' CHECK(rarity IN ('common', 'rare', 'epic', 'legendary')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User badge achievements
CREATE TABLE user_badges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  badge_id INTEGER NOT NULL,
  earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  earned_for TEXT, -- What action earned this badge
  course_id INTEGER, -- If earned for completing a course
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (badge_id) REFERENCES badges(id) ON DELETE CASCADE,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE SET NULL,
  UNIQUE(user_id, badge_id)
);

-- File uploads for interactive content
CREATE TABLE file_uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  file_path TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  file_type TEXT NOT NULL,
  upload_type TEXT DEFAULT 'interactive_content', -- interactive_content, course_image, etc.
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Notifications for users
CREATE TABLE notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  type TEXT DEFAULT 'info' CHECK(type IN ('info', 'success', 'warning', 'error')),
  is_read BOOLEAN DEFAULT 0,
  read_at DATETIME,
  action_url TEXT, -- Optional URL for notification action
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Enhanced usage tracking with interactive features
CREATE TABLE usage_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  month TEXT NOT NULL, -- '2025-08' format
  slides_created INTEGER DEFAULT 0,
  characters_used INTEGER DEFAULT 0, -- TTS characters
  courses_created INTEGER DEFAULT 0,
  interactive_slides_created INTEGER DEFAULT 0, -- New interactive slides
  students_enrolled INTEGER DEFAULT 0, -- Students enrolled in user's courses
  certificates_issued INTEGER DEFAULT 0, -- Certificates generated
  last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, month)
);

-- Course views/analytics (enhanced)
CREATE TABLE course_views (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course_id INTEGER NOT NULL,
  user_id INTEGER, -- NULL for anonymous views
  slide_id INTEGER,
  viewer_ip TEXT,
  viewer_user_agent TEXT,
  slide_number INTEGER,
  time_spent INTEGER DEFAULT 0, -- Time spent on this slide in seconds
  interactions_count INTEGER DEFAULT 0, -- Number of interactions
  viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  session_id TEXT, -- To track unique viewing sessions
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (slide_id) REFERENCES slides(id) ON DELETE CASCADE
);

-- User sessions (unchanged)
CREATE TABLE user_sessions (
  id TEXT PRIMARY KEY, -- UUID
  user_id INTEGER NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
  user_agent TEXT,
  ip_address TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_courses_user_id ON courses(user_id);
CREATE INDEX idx_courses_slug ON courses(slug);
CREATE INDEX idx_courses_status ON courses(status);
CREATE INDEX idx_slides_course_id ON slides(course_id);
CREATE INDEX idx_slides_type ON slides(slide_type);
CREATE INDEX idx_hotspots_slide_id ON slide_hotspots(slide_id);
CREATE INDEX idx_quiz_questions_slide_id ON quiz_questions(slide_id);
CREATE INDEX idx_drag_drop_slide_id ON drag_drop_items(slide_id);
CREATE INDEX idx_timeline_slide_id ON timeline_events(slide_id);
CREATE INDEX idx_before_after_slide_id ON before_after_content(slide_id);
CREATE INDEX idx_student_progress_user_course ON student_progress(user_id, course_id);
CREATE INDEX idx_student_progress_slide ON student_progress(slide_id);
CREATE INDEX idx_course_enrollments_user ON course_enrollments(user_id);
CREATE INDEX idx_course_enrollments_course ON course_enrollments(course_id);
CREATE INDEX idx_student_notes_user_course ON student_notes(user_id, course_id);
CREATE INDEX idx_discussions_course ON course_discussions(course_id);
CREATE INDEX idx_discussions_slide ON course_discussions(slide_id);
CREATE INDEX idx_user_badges_user ON user_badges(user_id);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_usage_stats_user_month ON usage_stats(user_id, month);
CREATE INDEX idx_course_views_course_id ON course_views(course_id);
CREATE INDEX idx_course_views_user ON course_views(user_id);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);

-- Enhanced plan limits configuration with interactive features
INSERT INTO users (id, email, password_hash, name, plan_type, plan_features) VALUES 
(0, 'system@coursemaker.app', '', 'System', 'business', 
 '{"limits": {
   "free": {
     "courses": 1, 
     "slides_per_course": 5, 
     "characters_per_month": 0, 
     "interactive_slides": 0,
     "students_per_course": 0,
     "features": ["basic_conversion"]
   }, 
   "pro": {
     "courses": -1, 
     "slides_per_course": 200, 
     "characters_per_month": 100000, 
     "interactive_slides": 50,
     "students_per_course": 100,
     "features": ["basic_conversion", "neural2_voices", "interactive_slides", "course_sharing", "analytics", "student_tracking"]
   }, 
   "business": {
     "courses": -1, 
     "slides_per_course": -1, 
     "characters_per_month": 500000, 
     "interactive_slides": -1,
     "students_per_course": -1,
     "features": ["basic_conversion", "neural2_voices", "chirp3_voices", "interactive_slides", "course_sharing", "analytics", "student_tracking", "gamification", "white_label", "team_seats", "advanced_interactions"]
   }
 }}');

-- Sample badges for gamification
INSERT INTO badges (name, description, icon_url, points_required, rarity) VALUES
('First Course', 'Created your first course', NULL, 0, 'common'),
('Course Creator', 'Created 5 courses', NULL, 250, 'common'),
('Voice Master', 'Generated 10 hours of narration', NULL, 500, 'rare'),
('Interactive Designer', 'Created 10 interactive slides', NULL, 300, 'rare'),
('Student Favorite', 'Course viewed by 100+ students', NULL, 1000, 'epic'),
('Course Master', 'Created 25 courses', NULL, 2500, 'epic'),
('Engagement Expert', 'Average student completion rate > 80%', NULL, 5000, 'legendary');

-- Sample data for testing (unchanged)
INSERT INTO users (email, password_hash, name, plan_type) VALUES 
('demo@coursemaker.app', '$2b$10$example_hash_here', 'Demo User', 'pro'),
('test@coursemaker.app', '$2b$10$example_hash_here', 'Test User', 'free');

-- Triggers to update timestamps
CREATE TRIGGER update_users_timestamp 
  AFTER UPDATE ON users
  BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_courses_timestamp 
  AFTER UPDATE ON courses
  BEGIN
    UPDATE courses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

CREATE TRIGGER update_slides_timestamp 
  AFTER UPDATE ON slides
  BEGIN
    UPDATE slides SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
  END;

-- Enhanced view for easy plan limit checking
CREATE VIEW user_plan_limits AS
SELECT 
  u.id,
  u.email,
  u.plan_type,
  u.total_points,
  u.level,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.courses') as max_courses,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.slides_per_course') as max_slides_per_course,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.characters_per_month') as max_characters_per_month,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.interactive_slides') as max_interactive_slides,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.students_per_course') as max_students_per_course,
  json_extract(system_user.plan_features, '$.limits.' || u.plan_type || '.features') as available_features
FROM users u
CROSS JOIN (SELECT plan_features FROM users WHERE id = 0) as system_user
WHERE u.id > 0;