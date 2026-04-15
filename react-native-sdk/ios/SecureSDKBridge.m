#import <React/RCTBridgeModule.h>

/**
 * Declarations only — implementations live in SecureSDKModule.swift and delegate to SecuritySdk (ios-sdk).
 * Keeps a single source of truth in Swift; no duplicate crypto or JSON logic in Objective-C.
 */
@interface RCT_EXTERN_MODULE (SecureSDK, NSObject)

RCT_EXTERN_METHOD(initialize : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(configureServerPublicKey : (NSString *)base64 resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(configurePinning : (NSString *)configJson resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getPublicKey : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(rotateKeys : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getDeviceRegistrationPayload : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureRequest : (NSString *)path bodyJson : (NSString *)bodyJson resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(secureRequestPinned : (NSString *)url bodyJson : (NSString *)bodyJson stepUpToken : (NSString *)stepUpToken resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(pinnedPost : (NSString *)url headersJson : (NSString *)headersJson bodyJson : (NSString *)bodyJson resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(signStepUp : (NSString *)message resolve : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getDeviceId : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getSecurityStatus : (RCTPromiseResolveBlock)resolve reject : (RCTPromiseRejectBlock)reject)

@end
