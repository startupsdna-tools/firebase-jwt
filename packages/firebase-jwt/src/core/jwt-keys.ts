import * as jose from 'jose';

export const GOOGLE_PUBLIC_KEYS_URL =
  'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
export const GOOGLE_IDENTITYTOOLKIT_PUBLIC_KEYS_URL =
  'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys';

export class JwtKeysProvider {
  private keys: Record<string, any> = {};

  constructor(private readonly keysUrl: string) {}

  getter(): jose.JWTVerifyGetKey {
    return async (protectedHeader) => {
      const { kid, alg } = protectedHeader;
      if (!kid) {
        throw new JwtKeysProviderError('Missing "kid" parameter in JWT header');
      }
      return this.getKey(kid, alg);
    };
  }

  protected async getKey(kid: string, alg: string) {
    if (!this.keys[kid]) {
      this.keys = await fetch(this.keysUrl)
        .then((response) => {
          return response.json();
        })
        .catch((err) => {
          throw new JwtKeysProviderError(
            `Failed to fetch public keys: ${err.message}`
          );
        });
    }

    if (!this.keys[kid]) {
      throw new JwtKeysProviderError(`Public key not found for kid: ${kid}`);
    }

    if (typeof this.keys[kid] === 'string') {
      try {
        this.keys[kid] = await jose.importX509(this.keys[kid], alg);
      } catch (e) {
        throw new JwtKeysProviderError(
          `Failed to import public key for kid: ${kid}`
        );
      }
    }

    return this.keys[kid];
  }
}

export class JwtKeysProviderError extends Error {
  constructor(message: string) {
    super(message);
  }
}
