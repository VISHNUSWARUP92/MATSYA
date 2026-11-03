
import { getApp, getApps, initializeApp } from "firebase/app";

import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  onAuthStateChanged,
  signOut,
} from "firebase/auth";

// Firebase configuration
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

// Validate configuration
const requiredKeys = [
  "apiKey",
  "authDomain",
  "projectId",
  "appId",
];

const missingKeys = requiredKeys.filter(
  (key) => !firebaseConfig[key]
);

if (missingKeys.length > 0) {
  throw new Error(
    `Firebase configuration missing: ${missingKeys.join(", ")}. Check your .env file.`
  );
}

// Initialize Firebase only once
const app = getApps().length
  ? getApp()
  : initializeApp(firebaseConfig);

// Initialize Authentication
export const auth = getAuth(app);

// Google Authentication Provider
export const googleProvider = new GoogleAuthProvider();

googleProvider.setCustomParameters({
  prompt: "select_account",
});

// Export authentication methods
export {
  signInWithPopup,
  onAuthStateChanged,
  signOut,
};

export default app;
