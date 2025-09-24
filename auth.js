// auth.js - Authentication and database utilities for CourseMaker
// Enhanced with Interactive Learning Features
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Database connection
const DB_PATH = path.join(__dirname, 'coursemaker.db');

class Database {
  constructor() {
    this.db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('Error opening database:', err);
      } else {
        console.log('Connected to SQLite database');
        this.initializeDatabase();
      }
    });
  }

  // Initialize database with schema if needed
  async initializeDatabase() {
    return new Promise((resolve, reject) => {
      this.db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
        if (err) {
          reject(err);
        } else if (!row) {
          console.log('Database tables not found, creating schema...');
          // Read and execute schema file
          const fs = require('fs');
          const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
          this.db.exec(schema, (err) => {
            if (err) {
              console.error('Error creating schema:', err);
              reject(err);
            } else {
              console.log('Database schema created successfully');
              resolve();
            }
          });
        } else {
          resolve();
        }
      });
    });
  }

  // Promisify database methods for easier async/await usage
  run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) reject(err);
        else resolve({ id: this.lastID, changes: this.changes });
      });
    });
  }

  get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  }

  all(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  close() {
    return new Promise((resolve, reject) => {
      this.db.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

class AuthManager {
  constructor(database) {
    this.db = database;
    this.sessions = new Map(); // In-memory session store for simplicity
  }

  // Hash password
  async hashPassword(password) {
    return bcrypt.hash(password, 12);
  }

  // Verify password
  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }

  // Register new user
  async registerUser(email, password, name = '', planType = 'free') {
    try {
      // Check if user already exists
      const existingUser = await this.db.get('SELECT id FROM users WHERE email = ?', [email]);
      if (existingUser) {
        throw new Error('Email already registered');
      }

      // Hash password
      const passwordHash = await this.hashPassword(password);

      // Create user
      const result = await this.db.run(
        'INSERT INTO users (email, password_hash, name, plan_type) VALUES (?, ?, ?, ?)',
        [email, passwordHash, name, planType]
      );

      // Create initial usage stats for current month
      const currentMonth = new Date().toISOString().substring(0, 7); // YYYY-MM
      await this.db.run(
        'INSERT INTO usage_stats (user_id, month) VALUES (?, ?)',
        [result.id, currentMonth]
      );

      // Return user without password
      return {
        id: result.id,
        email,
        name,
        planType,
        created: true
      };
    } catch (error) {
      throw new Error(`Registration failed: ${error.message}`);
    }
  }

  // Login user
  async loginUser(email, password) {
    try {
      // Get user from database
      const user = await this.db.get(
        'SELECT id, email, password_hash, name, plan_type, is_active FROM users WHERE email = ?',
        [email]
      );

      if (!user || !user.is_active) {
        throw new Error('Invalid credentials');
      }

      // Verify password
      const isValid = await this.verifyPassword(password, user.password_hash);
      if (!isValid) {
        throw new Error('Invalid credentials');
      }

      // Update last login
      await this.db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

      // Create session
      const sessionId = uuidv4();
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

      await this.db.run(
        'INSERT INTO user_sessions (id, user_id, expires_at) VALUES (?, ?, ?)',
        [sessionId, user.id, expiresAt.toISOString()]
      );

      // Store session in memory for quick access
      this.sessions.set(sessionId, {
        userId: user.id,
        email: user.email,
        planType: user.plan_type,
        expiresAt
      });

      return {
        sessionId,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          planType: user.plan_type
        }
      };
    } catch (error) {
      throw new Error(`Login failed: ${error.message}`);
    }
  }

  // Validate session
  async validateSession(sessionId) {
    if (!sessionId) return null;

    // Check memory cache first
    const cachedSession = this.sessions.get(sessionId);
    if (cachedSession && cachedSession.expiresAt > new Date()) {
      return cachedSession;
    }

    // Check database
    try {
      const session = await this.db.get(`
        SELECT s.id, s.user_id, s.expires_at, u.email, u.name, u.plan_type, u.is_active
        FROM user_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.id = ? AND s.expires_at > datetime('now') AND u.is_active = 1
      `, [sessionId]);

      if (!session) {
        this.sessions.delete(sessionId);
        return null;
      }

      // Update memory cache
      const sessionData = {
        userId: session.user_id,
        email: session.email,
        name: session.name,
        planType: session.plan_type,
        expiresAt: new Date(session.expires_at)
      };
      this.sessions.set(sessionId, sessionData);

      // Update last used
      await this.db.run('UPDATE user_sessions SET last_used = CURRENT_TIMESTAMP WHERE id = ?', [sessionId]);

      return sessionData;
    } catch (error) {
      console.error('Session validation error:', error);
      return null;
    }
  }

  // Logout user
  async logoutUser(sessionId) {
    if (!sessionId) return;

    try {
      // Remove from database
      await this.db.run('DELETE FROM user_sessions WHERE id = ?', [sessionId]);
      
      // Remove from memory
      this.sessions.delete(sessionId);
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  // Get user with plan limits using direct JSON parsing
  async getUserWithLimits(userId) {
    try {
      const user = await this.db.get(`
        SELECT * FROM users WHERE id = ?
      `, [userId]);

      if (!user) return null;

      // Get system user plan configuration
      const systemUser = await this.db.get(`
        SELECT plan_features FROM users WHERE id = 0
      `);

      if (!systemUser || !systemUser.plan_features) {
        console.error('System user plan features not found');
        return user;
      }

      const planFeatures = JSON.parse(systemUser.plan_features);
      const userPlanLimits = planFeatures.limits[user.plan_type];

      if (!userPlanLimits) {
        console.error(`Plan limits not found for plan type: ${user.plan_type}`);
        return user;
      }

      // Add limits to user object
      user.max_courses = userPlanLimits.courses;
      user.max_slides_per_course = userPlanLimits.slides_per_course;
      user.max_characters_per_month = userPlanLimits.characters_per_month;
      user.max_interactive_slides = userPlanLimits.interactive_slides;
      user.max_students_per_course = userPlanLimits.students_per_course;
      user.available_features = userPlanLimits.features;

      return user;
    } catch (error) {
      console.error('Error getting user with limits:', error);
      return null;
    }
  }

  // Enhanced plan limits checking with interactive features
  async checkPlanLimits(userId, action, additionalData = {}) {
    try {
      const user = await this.getUserWithLimits(userId);
      if (!user) return { allowed: false, reason: 'User not found' };

      const currentMonth = new Date().toISOString().substring(0, 7);
      const usage = await this.db.get(
        'SELECT * FROM usage_stats WHERE user_id = ? AND month = ?',
        [userId, currentMonth]
      );

      // If no usage record for this month, create it
      if (!usage) {
        await this.db.run(
          'INSERT INTO usage_stats (user_id, month) VALUES (?, ?)',
          [userId, currentMonth]
        );
        const newUsage = { 
          slides_created: 0, 
          characters_used: 0, 
          courses_created: 0,
          interactive_slides_created: 0,
          students_enrolled: 0,
          certificates_issued: 0
        };
        return this.checkLimitsAgainstUsage(user, newUsage, action, additionalData);
      }

      return this.checkLimitsAgainstUsage(user, usage, action, additionalData);
    } catch (error) {
      console.error('Error checking plan limits:', error);
      return { allowed: false, reason: 'Error checking limits' };
    }
  }

  checkLimitsAgainstUsage(user, usage, action, data) {
    switch (action) {
      case 'create_course':
        if (user.max_courses !== -1 && usage.courses_created >= user.max_courses) {
          return { allowed: false, reason: `Plan limit: ${user.max_courses} courses max` };
        }
        break;

      case 'add_slides':
        const slideCount = data.slideCount || 1;
        if (user.max_slides_per_course !== -1 && slideCount > user.max_slides_per_course) {
          return { allowed: false, reason: `Plan limit: ${user.max_slides_per_course} slides per course max` };
        }
        break;

      case 'create_interactive_slide':
        const interactiveCount = data.interactiveCount || 1;
        if (user.max_interactive_slides !== -1) {
          const currentInteractive = usage.interactive_slides_created || 0;
          if (currentInteractive + interactiveCount > user.max_interactive_slides) {
            return { 
              allowed: false, 
              reason: `Plan limit: ${user.max_interactive_slides} interactive slides max. Used: ${currentInteractive}` 
            };
          }
        }
        break;

      case 'enroll_students':
        const studentCount = data.studentCount || 1;
        if (user.max_students_per_course !== -1 && studentCount > user.max_students_per_course) {
          return { allowed: false, reason: `Plan limit: ${user.max_students_per_course} students per course max` };
        }
        break;

      case 'generate_audio':
        const characters = data.characters || 0;
        if (user.max_characters_per_month !== -1) {
          if (usage.characters_used + characters > user.max_characters_per_month) {
            return { 
              allowed: false, 
              reason: `Plan limit: ${user.max_characters_per_month} characters per month max. Used: ${usage.characters_used}` 
            };
          }
        }
        break;

      case 'use_feature':
        const feature = data.feature;
        if (!user.available_features || !user.available_features.includes(feature)) {
          return { allowed: false, reason: `Feature '${feature}' not available in ${user.plan_type} plan` };
        }
        break;
    }

    return { allowed: true };
  }

  // Enhanced usage tracking with interactive features
  async updateUsage(userId, type, amount = 1) {
    try {
      const currentMonth = new Date().toISOString().substring(0, 7);
      
      // Ensure usage record exists
      await this.db.run(`
        INSERT OR IGNORE INTO usage_stats (user_id, month) VALUES (?, ?)
      `, [userId, currentMonth]);

      // Update the specific usage type
      const column = type === 'slides' ? 'slides_created' : 
                   type === 'characters' ? 'characters_used' : 
                   type === 'courses' ? 'courses_created' :
                   type === 'interactive_slides' ? 'interactive_slides_created' :
                   type === 'students' ? 'students_enrolled' :
                   type === 'certificates' ? 'certificates_issued' : null;

      if (column) {
        await this.db.run(`
          UPDATE usage_stats 
          SET ${column} = ${column} + ?, last_updated = CURRENT_TIMESTAMP 
          WHERE user_id = ? AND month = ?
        `, [amount, userId, currentMonth]);
      }
    } catch (error) {
      console.error('Error updating usage:', error);
    }
  }
}

// Enhanced Course management with interactive features
class CourseManager {
  constructor(database) {
    this.db = database;
  }

  // Create a new course
  async createCourse(userId, title, description = '') {
    try {
      const slug = this.generateSlug(title);
      
      const result = await this.db.run(`
        INSERT INTO courses (user_id, title, description, slug)
        VALUES (?, ?, ?, ?)
      `, [userId, title, description, slug]);

      return {
        id: result.id,
        title,
        description,
        slug,
        status: 'draft'
      };
    } catch (error) {
      throw new Error(`Failed to create course: ${error.message}`);
    }
  }

  // Get courses for a user
  async getUserCourses(userId, limit = 50, offset = 0) {
    try {
      const courses = await this.db.all(`
        SELECT 
          c.*,
          COUNT(s.id) as actual_slide_count,
          SUM(s.duration) as total_duration
        FROM courses c
        LEFT JOIN slides s ON c.id = s.course_id
        WHERE c.user_id = ?
        GROUP BY c.id
        ORDER BY c.updated_at DESC
        LIMIT ? OFFSET ?
      `, [userId, limit, offset]);

      return courses;
    } catch (error) {
      console.error('Error getting user courses:', error);
      return [];
    }
  }

  // Add slides to a course
  async addSlidesToCourse(courseId, slideUrls, jobId) {
    try {
      // Start transaction
      await this.db.run('BEGIN TRANSACTION');

      for (let i = 0; i < slideUrls.length; i++) {
        await this.db.run(`
          INSERT INTO slides (course_id, slide_number, slide_type, image_url, title)
          VALUES (?, ?, ?, ?, ?)
        `, [courseId, i + 1, 'standard', slideUrls[i], `Slide ${i + 1}`]);
      }

      // Update course slide count
      await this.db.run(`
        UPDATE courses 
        SET slide_count = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `, [slideUrls.length, courseId]);

      await this.db.run('COMMIT');

      return { success: true, slidesAdded: slideUrls.length };
    } catch (error) {
      await this.db.run('ROLLBACK');
      throw new Error(`Failed to add slides: ${error.message}`);
    }
  }

 // Create interactive slide
async createInteractiveSlide(courseId, slideType, data) {
  try {
    await this.db.run('BEGIN TRANSACTION');

    // Get next slide number
    const result = await this.db.get(
      'SELECT MAX(slide_number) as max_num FROM slides WHERE course_id = ?',
      [courseId]
    );
    const slideNumber = (result.max_num || 0) + 1;

    // Choose an image URL (hotspots require a background image)
    const imageUrl =
      (data && data.imageUrl) ||
      (data && data.interactiveData && data.interactiveData.backgroundImage) ||
  '/interactive/placeholder.svg'; // last-resort fallback to satisfy NOT NULL

// 👉 add this log
console.log('createInteractiveSlide payload:', {
  slideType,
  imageUrl,
  keys: Object.keys(data || {})
});

// Create the slide  ✅ 8 columns, 8 placeholders
    const slideResult = await this.db.run(`
      INSERT INTO slides (course_id, slide_number, slide_type, title, content, image_url, interactive_data, points_value)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      courseId,
      slideNumber,
      slideType,
      data.title || `${slideType} Slide`,
      data.content || '',
      imageUrl,
      JSON.stringify(data.interactiveData || {}),
      data.pointsValue || 0
    ]);

      const slideId = slideResult.id;

      // Create type-specific data
      switch (slideType) {
        case 'hotspot':
          if (data.hotspots) {
            for (const hotspot of data.hotspots) {
await this.db.run(`
  INSERT INTO slide_hotspots (slide_id, x_position, y_position, title, description, icon_type, audio_url)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`, [
  slideId,
  hotspot.x,
  hotspot.y,
  hotspot.title,
  hotspot.description || '', // ← added fallback empty string
  hotspot.icon || 'info',
  hotspot.audioUrl || null   // ← added fallback null
]);

            }
          }
          break;

        case 'quiz':
        case 'assessment':
          if (data.questions) {
            for (const question of data.questions) {
              await this.db.run(`
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

        case 'drag_drop':
          try {
            // Handle both old format (data.items) and new format (data.interactiveData.dragItems)
            const dragItems = data.interactiveData?.dragItems || data.items || [];
            const dropZones = data.interactiveData?.dropZones || data.zones || [];
            
            console.log('Processing drag_drop items:', { dragItems, dropZones });
            
            // Insert drag items
            for (const item of dragItems) {
              console.log('Inserting drag item:', item);
              await this.db.run(`
                INSERT INTO drag_drop_items (slide_id, item_text, item_type, correct_match_id, x_position, y_position)
                VALUES (?, ?, ?, ?, ?, ?)
              `, [slideId, item.text, 'draggable', item.correctMatchId || null, item.x || 0, item.y || 0]);
            }
            
            // Insert drop zones
            for (const zone of dropZones) {
              console.log('Inserting drop zone:', zone);
              await this.db.run(`
                INSERT INTO drag_drop_items (slide_id, item_text, item_type, correct_match_id, x_position, y_position)
                VALUES (?, ?, ?, ?, ?, ?)
              `, [slideId, zone.label, 'drop_zone', null, zone.x || 0, zone.y || 0]);
            }
          } catch (dragDropError) {
            console.error('Error processing drag_drop items:', dragDropError);
            throw dragDropError;
          }
          break;

        case 'timeline':
          if (data.events) {
            for (const event of data.events) {
              await this.db.run(`
                INSERT INTO timeline_events (slide_id, event_date, event_title, event_description, event_order)
                VALUES (?, ?, ?, ?, ?)
              `, [slideId, event.date, event.title, event.description, event.order]);
            }
          }
          break;

        case 'before_after':
          if (data.comparison) {
            await this.db.run(`
              INSERT INTO before_after_content (slide_id, before_image_url, after_image_url, before_title, after_title, before_description, after_description)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
              slideId,
              data.comparison.beforeImage,
              data.comparison.afterImage,
              data.comparison.beforeTitle || 'Before',
              data.comparison.afterTitle || 'After',
              data.comparison.beforeDescription || '',
              data.comparison.afterDescription || ''
            ]);
          }
          break;
      }

      await this.db.run('COMMIT');

      return { success: true, slideId, slideNumber };
    } catch (error) {
      await this.db.run('ROLLBACK');
      throw new Error(`Failed to create interactive slide: ${error.message}`);
    }
  }

  // Generate URL-friendly slug
  generateSlug(title) {
    const baseSlug = title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .substring(0, 50);
    
    // Add random suffix to ensure uniqueness
    const suffix = Math.random().toString(36).substring(2, 8);
    return `${baseSlug}-${suffix}`;
  }

  // Get public course by slug
  async getPublicCourse(slug) {
    try {
      const course = await this.db.get(`
        SELECT c.*, u.name as author_name
        FROM courses c
        JOIN users u ON c.user_id = u.id
        WHERE c.slug = ? AND c.is_public = 1 AND c.status = 'published'
      `, [slug]);

      if (!course) return null;

      const slides = await this.db.all(`
        SELECT * FROM slides 
        WHERE course_id = ? 
        ORDER BY slide_number
      `, [course.id]);

      return { ...course, slides };
    } catch (error) {
      console.error('Error getting public course:', error);
      return null;
    }
  }
}

// New manager classes for interactive features
class ProgressManager {
  constructor(database) {
    this.db = database;
  }

  // Track student progress on a slide
  async updateSlideProgress(userId, courseId, slideId, data = {}) {
    try {
      await this.db.run(`
        INSERT OR REPLACE INTO student_progress 
        (user_id, course_id, slide_id, completed, score, time_spent, interactions_count, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        userId,
        courseId, 
        slideId,
        data.completed ? 1 : 0,
        data.score || null,
        data.timeSpent || 0,
        data.interactionsCount || 0,
        data.completed ? new Date().toISOString() : null
      ]);

      // Update overall course progress
      await this.updateCourseProgress(userId, courseId);

      return { success: true };
    } catch (error) {
      throw new Error(`Failed to update progress: ${error.message}`);
    }
  }

  // Calculate and update overall course progress
  async updateCourseProgress(userId, courseId) {
    try {
      // Get total slides in course
      const totalSlides = await this.db.get(
        'SELECT COUNT(*) as count FROM slides WHERE course_id = ?',
        [courseId]
      );

      // Get completed slides
      const completedSlides = await this.db.get(`
        SELECT COUNT(*) as count FROM student_progress 
        WHERE user_id = ? AND course_id = ? AND completed = 1
      `, [userId, courseId]);

      const progress = totalSlides.count > 0 ? 
        (completedSlides.count / totalSlides.count) * 100 : 0;

      const isCompleted = progress >= 100;

      // Update or create enrollment record
      await this.db.run(`
        INSERT OR REPLACE INTO course_enrollments 
        (user_id, course_id, status, progress_percentage, completed_at)
        VALUES (?, ?, ?, ?, ?)
      `, [
        userId,
        courseId,
        isCompleted ? 'completed' : 'in_progress',
        progress,
        isCompleted ? new Date().toISOString() : null
      ]);

      return { progress, isCompleted };
    } catch (error) {
      console.error('Error updating course progress:', error);
      return { progress: 0, isCompleted: false };
    }
  }

  // Get student progress for a course
  async getCourseProgress(userId, courseId) {
    try {
      const enrollment = await this.db.get(`
        SELECT * FROM course_enrollments 
        WHERE user_id = ? AND course_id = ?
      `, [userId, courseId]);

      const slideProgress = await this.db.all(`
        SELECT * FROM student_progress 
        WHERE user_id = ? AND course_id = ?
        ORDER BY slide_id
      `, [userId, courseId]);

      return {
        enrollment: enrollment || null,
        slideProgress: slideProgress || []
      };
    } catch (error) {
      console.error('Error getting course progress:', error);
      return { enrollment: null, slideProgress: [] };
    }
  }
}

class DiscussionManager {
  constructor(database) {
    this.db = database;
  }

  // Create a discussion post
  async createPost(courseId, userId, content, slideId = null, parentId = null) {
    try {
      const result = await this.db.run(`
        INSERT INTO course_discussions (course_id, slide_id, user_id, parent_id, content)
        VALUES (?, ?, ?, ?, ?)
      `, [courseId, slideId, userId, parentId, content]);

      return { success: true, postId: result.id };
    } catch (error) {
      throw new Error(`Failed to create post: ${error.message}`);
    }
  }

  // Get discussions for a course or slide
  async getDiscussions(courseId, slideId = null, limit = 50, offset = 0) {
    try {
      const discussions = await this.db.all(`
        SELECT 
          d.*,
          u.name as author_name
        FROM course_discussions d
        JOIN users u ON d.user_id = u.id
        WHERE d.course_id = ? AND (? IS NULL OR d.slide_id = ?) AND d.parent_id IS NULL
        ORDER BY d.created_at DESC
        LIMIT ? OFFSET ?
      `, [courseId, slideId, slideId, limit, offset]);

      // Get replies for each discussion
      for (const discussion of discussions) {
        const replies = await this.db.all(`
          SELECT 
            d.*,
            u.name as author_name
          FROM course_discussions d
          JOIN users u ON d.user_id = u.id
          WHERE d.parent_id = ?
          ORDER BY d.created_at ASC
        `, [discussion.id]);
        
        discussion.replies = replies;
      }

      return discussions;
    } catch (error) {
      console.error('Error getting discussions:', error);
      return [];
    }
  }
}

class AnalyticsManager {
  constructor(database) {
    this.db = database;
  }

  // Track course view
  async trackCourseView(courseId, userId = null, slideId = null, data = {}) {
    try {
      await this.db.run(`
        INSERT INTO course_views 
        (course_id, user_id, slide_id, viewer_ip, viewer_user_agent, slide_number, time_spent, interactions_count, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        courseId,
        userId,
        slideId,
        data.ip || null,
        data.userAgent || null,
        data.slideNumber || null,
        data.timeSpent || 0,
        data.interactionsCount || 0,
        data.sessionId || null
      ]);

      return { success: true };
    } catch (error) {
      console.error('Error tracking course view:', error);
      return { success: false };
    }
  }

  // Get course analytics
  async getCourseAnalytics(courseId, period = '30d') {
    try {
      const analytics = {
        totalViews: 0,
        uniqueViewers: 0,
        averageTimeSpent: 0,
        completionRate: 0,
        slideAnalytics: []
      };

      // Total views
      const viewsResult = await this.db.get(`
        SELECT COUNT(*) as count FROM course_views 
        WHERE course_id = ? AND viewed_at > datetime('now', '-${period}')
      `, [courseId]);
      analytics.totalViews = viewsResult.count;

      // Unique viewers
      const uniqueResult = await this.db.get(`
        SELECT COUNT(DISTINCT session_id) as count FROM course_views 
        WHERE course_id = ? AND viewed_at > datetime('now', '-${period}')
      `, [courseId]);
      analytics.uniqueViewers = uniqueResult.count;

      // Average time spent
      const timeResult = await this.db.get(`
        SELECT AVG(time_spent) as avg_time FROM course_views 
        WHERE course_id = ? AND viewed_at > datetime('now', '-${period}')
      `, [courseId]);
      analytics.averageTimeSpent = timeResult.avg_time || 0;

      // Completion rate
      const enrollments = await this.db.get(`
        SELECT COUNT(*) as total, 
               COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed
        FROM course_enrollments 
        WHERE course_id = ?
      `, [courseId]);
      
      if (enrollments.total > 0) {
        analytics.completionRate = (enrollments.completed / enrollments.total) * 100;
      }

      return analytics;
    } catch (error) {
      console.error('Error getting course analytics:', error);
      return null;
    }
  }
}

class GamificationManager {
  constructor(database) {
    this.db = database;
  }

  // Award points to user
  async awardPoints(userId, points, reason = '', courseId = null) {
    try {
      // Update user total points
      await this.db.run(`
        UPDATE users 
        SET total_points = total_points + ?
        WHERE id = ?
      `, [points, userId]);

      // Update user level based on points
      await this.updateUserLevel(userId);

      return { success: true };
    } catch (error) {
      console.error('Error awarding points:', error);
      return { success: false };
    }
  }

  // Update user level based on points
  async updateUserLevel(userId) {
    try {
      const user = await this.db.get('SELECT total_points FROM users WHERE id = ?', [userId]);
      if (!user) return;

      // Level calculation: every 1000 points = 1 level
      const newLevel = Math.floor(user.total_points / 1000) + 1;

      await this.db.run(`
        UPDATE users SET level = ? WHERE id = ?
      `, [newLevel, userId]);

      return newLevel;
    } catch (error) {
      console.error('Error updating user level:', error);
      return 1;
    }
  }

  // Award badge to user
  async awardBadge(userId, badgeId, reason = '', courseId = null) {
    try {
      // Check if user already has this badge
      const existing = await this.db.get(`
        SELECT id FROM user_badges WHERE user_id = ? AND badge_id = ?
      `, [userId, badgeId]);

      if (existing) {
        return { success: false, reason: 'Badge already earned' };
      }

      // Award the badge
      await this.db.run(`
        INSERT INTO user_badges (user_id, badge_id, earned_for, course_id)
        VALUES (?, ?, ?, ?)
      `, [userId, badgeId, reason, courseId]);

      return { success: true };
    } catch (error) {
      console.error('Error awarding badge:', error);
      return { success: false };
    }
  }

  // Get user badges and points
  async getUserGamification(userId) {
    try {
      const user = await this.db.get(`
        SELECT total_points, level FROM users WHERE id = ?
      `, [userId]);

      const badges = await this.db.all(`
        SELECT 
          b.*,
          ub.earned_at,
          ub.earned_for
        FROM user_badges ub
        JOIN badges b ON ub.badge_id = b.id
        WHERE ub.user_id = ?
        ORDER BY ub.earned_at DESC
      `, [userId]);

      return {
        points: user?.total_points || 0,
        level: user?.level || 1,
        badges: badges || []
      };
    } catch (error) {
      console.error('Error getting user gamification:', error);
      return { points: 0, level: 1, badges: [] };
    }
  }

  // Check and award automatic badges
  async checkAutomaticBadges(userId, action, data = {}) {
    try {
      switch (action) {
        case 'course_created':
          const courseCount = await this.db.get(`
            SELECT COUNT(*) as count FROM courses WHERE user_id = ?
          `, [userId]);

          if (courseCount.count === 1) {
            await this.awardBadge(userId, 1, 'Created first course'); // First Course badge
          } else if (courseCount.count === 5) {
            await this.awardBadge(userId, 2, 'Created 5 courses'); // Course Creator badge
          } else if (courseCount.count === 25) {
            await this.awardBadge(userId, 6, 'Created 25 courses'); // Course Master badge
          }
          break;

        case 'interactive_slide_created':
          const interactiveCount = await this.db.get(`
            SELECT COUNT(*) as count FROM slides 
            WHERE course_id IN (SELECT id FROM courses WHERE user_id = ?) 
            AND slide_type != 'standard'
          `, [userId]);

          if (interactiveCount.count === 10) {
            await this.awardBadge(userId, 4, 'Created 10 interactive slides'); // Interactive Designer badge
          }
          break;

        case 'tts_generated':
          const audioUsage = await this.db.get(`
            SELECT SUM(characters_used) as total FROM usage_stats WHERE user_id = ?
          `, [userId]);

          // 10 hours ≈ 36,000 characters (average speaking rate)
          if (audioUsage.total >= 36000) {
            await this.awardBadge(userId, 3, 'Generated 10 hours of narration'); // Voice Master badge
          }
          break;
      }
    } catch (error) {
      console.error('Error checking automatic badges:', error);
    }
  }
}

module.exports = {
  Database,
  AuthManager,
  CourseManager,
  ProgressManager,
  DiscussionManager,
  AnalyticsManager,
  GamificationManager
};