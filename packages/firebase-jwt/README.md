# Firebase Jwt Verifier

This package provides a simple way to verify Firebase JWT tokens without the need to use the Firebase Admin SDK.

Usage:

```typescript
import { FirebaseJwtVerifier } from '@startupsdna-tools/firebase-jwt';

const firebaseJwt = new FirebaseJwtVerifier({
  projectId: 'your-firebase-project-id',
  tenentId: 'your-idp-tenent-id', // optional
});

const decodedToken = await firebaseJwt.verifyIdToken(token);
```
