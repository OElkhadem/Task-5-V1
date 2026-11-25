import Joi from 'joi';
import bcrypt from 'bcryptjs';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER (secured)
// =============================================================================
//
// Defence in depth against NoSQL injection:
//   1. express-mongo-sanitize (app.js) strips any key starting with "$" or
//      containing "." from req.body / req.query / req.params, so operators such
//      as $ne, $gt, $regex and $where never reach this file.
//   2. Joi (below) checks the TYPE and SHAPE of what is left: credentials must be
//      plain strings, and search only accepts an allow-list of known fields.
//   3. The query is built from the validated values only, never from req.query.
//   4. Responses use an explicit allow-list of public fields.

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(64).required(),
  password: Joi.string().min(1).max(128).required()
});

// Only these query parameters are understood. Anything else is dropped
// (stripUnknown) instead of being passed to the database.
const searchSchema = Joi.object({
  name: Joi.string().trim().max(60).allow(''),
  department: Joi.string().trim().max(60).allow('')
});

// Compared against when the username does not exist, so a wrong username and a
// wrong password take about the same time (no username enumeration by timing).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 10);

// Escape regex metacharacters so user text is matched literally.
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// What a signed-in instructor gets back. No password, apiKey or private contact data.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) {
      return res
        .status(400)
        .json({ message: 'username and password must be non-empty strings' });
    }

    // `value.username` is guaranteed to be a string here, so it can only be
    // matched as a literal value, never interpreted as an operator.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');

    // The password is compared as a bcrypt hash, not inside the query, so there is
    // nothing for $regex/$ne to probe.
    const ok = await bcrypt.compare(value.password, instructor ? instructor.password : DUMMY_HASH);
    if (!instructor || !ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory: limited fields only.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search?name=Smith&department=Math
export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query, { stripUnknown: true });
    if (error) {
      return res.status(400).json({ message: 'name and department must be plain strings' });
    }

    // Build the filter ourselves from validated values.
    const filter = {};
    if (value.name) filter.name = { $regex: escapeRegex(value.name), $options: 'i' };
    if (value.department) filter.department = value.department;

    const instructors = await Instructor.find(filter)
      .select('name department role') // public fields only
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}