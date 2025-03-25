export interface RegistrationResponseData {
  publicKey: {
    challenge: string;
    rp: {
      name: string;
    };
    user: {
      id: string;
      name: string;
      displayName: string;
    };
    pubKeyCredParams: Array<{
      type: string;
      alg: number;
    }>;
    timeout?: number;
    attestation?: string;
    authenticatorSelection?: {
      authenticatorAttachment?: string;
      requireResidentKey?: boolean;
      userVerification?: string;
    };
    extensions?: AuthenticationExtensionsClientInputs;
  };
}

export interface CredentialCreationOptions {
  publicKey: {
    challenge: Uint8Array;
    rp: {
      name: string;
    };
    user: {
      id: Uint8Array;
      name: string;
      displayName: string;
    };
    pubKeyCredParams: any;
    timeout?: number;
    attestation?: any;
    authenticatorSelection?: any;
    extensions?: any;
  };
}

export interface AuthenticationResponseData {
  publicKey: {
    challenge: string;
    allowCredentials?: {
      type: string;
      id: string;
      transports?: any;
    }[];
    timeout?: number;
    userVerification?: any;
    extensions?: any;
  };
}