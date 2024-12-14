import * as jose from 'jose';
import {
  GOOGLE_IDENTITYTOOLKIT_PUBLIC_KEYS_URL,
  GOOGLE_PUBLIC_KEYS_URL,
  JwtKeysProvider,
} from './jwt-keys';

export type JWTFirebaseClaims = {
  /**
   * The audience for which this token is intended.
   *
   * This value is a string equal to your Firebase project ID, the unique
   * identifier for your Firebase project, which can be found in [your project's
   * settings](https://console.firebase.google.com/project/_/settings/general/android:com.random.android).
   */
  aud: string;
  /**
   * Time, in seconds since the Unix epoch, when the end-user authentication
   * occurred.
   *
   * This value is not set when this particular ID token was created, but when the
   * user initially logged in to this session. In a single session, the Firebase
   * SDKs will refresh a user's ID tokens every hour. Each ID token will have a
   * different [`iat`](#iat) value, but the same `auth_time` value.
   */
  auth_time: number;
  /**
   * The email of the user to whom the ID token belongs, if available.
   */
  email?: string;
  /**
   * Whether or not the email of the user to whom the ID token belongs is
   * verified, provided the user has an email.
   */
  email_verified?: boolean;
  /**
   * Information about the sign in event, including which sign in provider was
   * used and provider-specific identity details.
   *
   * This data is provided by the Firebase Authentication service and is a
   * reserved claim in the ID token.
   */
  firebase: {
    /**
     * Provider-specific identity details corresponding
     * to the provider used to sign in the user.
     */
    identities: {
      [key: string]: any;
    };
    /**
     * The ID of the provider used to sign in the user.
     * One of `"anonymous"`, `"password"`, `"facebook.com"`, `"github.com"`,
     * `"google.com"`, `"twitter.com"`, `"apple.com"`, `"microsoft.com"`,
     * `"yahoo.com"`, `"phone"`, `"playgames.google.com"`, `"gc.apple.com"`,
     * or `"custom"`.
     *
     * Additional Identity Platform provider IDs include `"linkedin.com"`,
     * OIDC and SAML identity providers prefixed with `"saml."` and `"oidc."`
     * respectively.
     */
    sign_in_provider: string;
    /**
     * The type identifier or `factorId` of the second factor, provided the
     * ID token was obtained from a multi-factor authenticated user.
     * For phone, this is `"phone"`.
     */
    sign_in_second_factor?: string;
    /**
     * The `uid` of the second factor used to sign in, provided the
     * ID token was obtained from a multi-factor authenticated user.
     */
    second_factor_identifier?: string;
    /**
     * The ID of the tenant the user belongs to, if available.
     */
    tenant?: string;
    [key: string]: any;
  };

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * As a convenience, this value is copied over to the [`uid`](#uid) property.
   */
  sub: string;

  /**
   * The `uid` corresponding to the user who the ID token belonged to.
   *
   * This value is not actually in the JWT token claims itself. It is added as a
   * convenience, and is set as the value of the [`sub`](#sub) property.
   */
  uid: string;
};

export type JWTFirebasePayload = jose.JWTPayload & JWTFirebaseClaims;

export type FirebaseJwtVerifierOptions = {
  projectId: string;
  tenantId?: string;
};

export class FirebaseJwtVerifier {
  private idTokenKeysProvider = new JwtKeysProvider(GOOGLE_PUBLIC_KEYS_URL);
  private sessionTokenKeysProvider = new JwtKeysProvider(
    GOOGLE_IDENTITYTOOLKIT_PUBLIC_KEYS_URL
  );
  constructor(private readonly options: FirebaseJwtVerifierOptions) {}

  async verifyIdToken(token: string): Promise<JWTFirebasePayload> {
    const { projectId } = this.options;
    return await this.verify(token, this.idTokenKeysProvider.getter(), {
      issuer: `https://securetoken.google.com/${projectId}`,
      audience: projectId,
    });
  }

  async verifySessionToken(token: string): Promise<JWTFirebasePayload> {
    const { projectId } = this.options;
    return await this.verify(token, this.sessionTokenKeysProvider.getter(), {
      issuer: `https://session.firebase.google.com/${projectId}`,
      audience: projectId,
    });
  }

  private async verify(
    token: string,
    keyGetter: jose.JWTVerifyGetKey,
    options?: jose.JWTVerifyOptions
  ): Promise<JWTFirebasePayload> {
    const { tenantId } = this.options;
    const res = await jose.jwtVerify(token, keyGetter, {
      algorithms: ['RS256'],
      requiredClaims: [
        'exp',
        'iat',
        'aud',
        'iss',
        'sub',
        'auth_time',
        'firebase',
      ],
      ...options,
    });

    const decoded = res.payload as JWTFirebasePayload;

    // verify tenantId
    if (tenantId && decoded.firebase.tenant !== tenantId) {
      throw new jose.errors.JWTClaimValidationFailed(
        'Invalid tenantId',
        res.payload,
        'firebase.tenant'
      );
    }

    // provide uid for compatibility with Firebase Admin SDK
    decoded.uid = decoded.sub;

    return decoded;
  }
}
