import { NativeModules, Platform } from 'react-native';

type NativeSecureSDKType = {
  /** Native entrypoint; not named `init` because Kotlin/ObjC reserve `init`. */
  initialize(): Promise<void>;
  configureServerPublicKey(base64Spki: string): Promise<void>;
  /** Configure certificate pinning for native HTTP client. JSON: { host: string, pins: string[] } */
  configurePinning(configJson: string): Promise<void>;
  getPublicKey(): Promise<string>;
  rotateKeys(): Promise<void>;
  getDeviceRegistrationPayload(): Promise<string>;
  /** Builds secure envelope only (no network). */
  secureRequest(path: string, bodyJson: string): Promise<string>;
  /** Sends secure request to backend using pinned native HTTP. */
  secureRequestPinned(url: string, bodyJson: string, stepUpToken?: string): Promise<string>;
  /** Sends arbitrary JSON POST using pinned native HTTP. */
  pinnedPost(url: string, headersJson: string, bodyJson: string): Promise<string>;
  /** Signs a UTF-8 message using device signing key; returns base64 signature. */
  signStepUp(message: string): Promise<string>;
  getDeviceId(): Promise<string>;
  getSecurityStatus(): Promise<string>;
};

const NativeSecureSDK = NativeModules.SecureSDK as NativeSecureSDKType | undefined;

export function getNativeModule(): NativeSecureSDKType {
  if (!NativeSecureSDK) {
    throw new Error(
      `SecureSDK native module is not linked. Platform=${Platform.OS}. ` +
        'Rebuild the app and ensure the native module is registered.',
    );
  }
  return NativeSecureSDK;
}
