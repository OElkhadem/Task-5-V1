import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 10;

// Fields that must never leave the server through a normal query or response.
const SECRET_FIELDS = ['password', 'apiKey', 'privateEmail', 'privatePhone'];

// Instructor Portal account.
//
// Secure version of the model:
//  - the password is stored as a bcrypt hash (pre('save') hook below), never plaintext
//  - every secret field is `select: false`, so a query does NOT return it unless the
//    code explicitly asks for it with .select('+field'). A forgotten .select() can
//    no longer leak a secret.
//  - toJSON strips the secrets again, as a second safety net if a full document is
//    ever serialised.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true, select: false }, // bcrypt hash
    department: { type: String },
    role: { type: String, enum: ['instructor', 'superadmin'], default: 'instructor' },

    // Private fields: never exposed by the directory, search or login.
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  {
    timestamps: true,
    toJSON: {
      transform(doc, ret) {
        for (const field of SECRET_FIELDS) delete ret[field];
        return ret;
      }
    }
  }
);

// Hash the password whenever it is new or changed. Runs for save() and create(),
// NOT for insertMany() or update queries (hash manually in those cases).
instructorSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
});

// The password field is select:false, so load the document with .select('+password')
// before calling this.
instructorSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

export const Instructor = mongoose.model('Instructor', instructorSchema);