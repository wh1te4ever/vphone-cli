// VPhoneObjC.m — ObjC wrappers for private Virtualization.framework APIs
#import "VPhoneObjC.h"
#import <objc/message.h>

// Private class forward declarations
@interface _VZMacHardwareModelDescriptor : NSObject
- (instancetype)init;
- (void)setPlatformVersion:(unsigned int)version;
- (void)setISA:(long long)isa;
- (void)setBoardID:(unsigned int)boardID;
@end

@interface VZMacHardwareModel (Private)
+ (instancetype)_hardwareModelWithDescriptor:(id)descriptor;
@end

@interface VZMacOSVirtualMachineStartOptions (Private)
- (void)_setForceDFU:(BOOL)force;
- (void)_setPanicAction:(BOOL)stop;
- (void)_setFatalErrorAction:(BOOL)stop;
- (void)_setStopInIBootStage1:(BOOL)stop;
- (void)_setStopInIBootStage2:(BOOL)stop;
@end

@interface VZMacOSBootLoader (Private)
- (void)_setROMURL:(NSURL *)url;
@end

@interface VZVirtualMachineConfiguration (Private)
- (void)_setDebugStub:(id)stub;
- (void)_setPanicDevice:(id)device;
- (void)_setCoprocessors:(NSArray *)coprocessors;
- (void)_setMultiTouchDevices:(NSArray *)devices;
@end

@interface VZMacPlatformConfiguration (Private)
- (void)_setProductionModeEnabled:(BOOL)enabled;
@end

// --- Implementation ---

VZMacHardwareModel *VPhoneCreateHardwareModel(void) {
  // Create descriptor with PV=3, ISA=2, boardID=0x90 (matches vrevm vresearch101)
  _VZMacHardwareModelDescriptor *desc = [[_VZMacHardwareModelDescriptor alloc] init];
  [desc setPlatformVersion:3];
  [desc setBoardID:0x90];
  [desc setISA:2];

  VZMacHardwareModel *model = [VZMacHardwareModel _hardwareModelWithDescriptor:desc];
  return model;
}

void VPhoneSetBootLoaderROMURL(VZMacOSBootLoader *bootloader, NSURL *romURL) {
  [bootloader _setROMURL:romURL];
}

void VPhoneConfigureStartOptions(VZMacOSVirtualMachineStartOptions *opts,
                                  BOOL forceDFU,
                                  BOOL stopOnPanic,
                                  BOOL stopOnFatalError) {
  [opts _setForceDFU:forceDFU];
  [opts _setStopInIBootStage1:NO];
  [opts _setStopInIBootStage2:NO];
  // Note: _setPanicAction: / _setFatalErrorAction: don't exist on
  // VZMacOSVirtualMachineStartOptions. Panic handling is done via
  // _VZPvPanicDeviceConfiguration set on VZVirtualMachineConfiguration.
}

void VPhoneSetGDBDebugStub(VZVirtualMachineConfiguration *config, NSInteger port) {
  Class stubClass = NSClassFromString(@"_VZGDBDebugStubConfiguration");
  if (!stubClass) {
    NSLog(@"[vphone] WARNING: _VZGDBDebugStubConfiguration not found");
    return;
  }
  // Use objc_msgSend to call initWithPort: with an NSInteger argument
  id (*initWithPort)(id, SEL, NSInteger) = (id (*)(id, SEL, NSInteger))objc_msgSend;
  id stub = initWithPort([stubClass alloc], NSSelectorFromString(@"initWithPort:"), port);
  [config _setDebugStub:stub];
}

void VPhoneSetPanicDevice(VZVirtualMachineConfiguration *config) {
  Class panicClass = NSClassFromString(@"_VZPvPanicDeviceConfiguration");
  if (!panicClass) {
    NSLog(@"[vphone] WARNING: _VZPvPanicDeviceConfiguration not found");
    return;
  }
  id device = [[panicClass alloc] init];
  [config _setPanicDevice:device];
}

void VPhoneSetCoprocessors(VZVirtualMachineConfiguration *config, NSArray *coprocessors) {
  [config _setCoprocessors:coprocessors];
}

void VPhoneDisableProductionMode(VZMacPlatformConfiguration *platform) {
  [platform _setProductionModeEnabled:NO];
}

// --- NVRAM ---

@interface VZMacAuxiliaryStorage (Private)
- (BOOL)_setDataValue:(NSData *)value forNVRAMVariableNamed:(NSString *)name error:(NSError **)error;
@end

BOOL VPhoneSetNVRAMVariable(VZMacAuxiliaryStorage *auxStorage, NSString *name, NSData *value) {
  NSError *error = nil;
  BOOL ok = [auxStorage _setDataValue:value forNVRAMVariableNamed:name error:&error];
  if (!ok) {
    NSLog(@"[vphone] NVRAM set '%@' failed: %@", name, error);
  }
  return ok;
}

// --- PL011 Serial Port ---

@interface _VZPL011SerialPortConfiguration : VZSerialPortConfiguration
@end

VZSerialPortConfiguration *VPhoneCreatePL011SerialPort(void) {
  Class cls = NSClassFromString(@"_VZPL011SerialPortConfiguration");
  if (!cls) {
    NSLog(@"[vphone] WARNING: _VZPL011SerialPortConfiguration not found");
    return nil;
  }
  return [[cls alloc] init];
}

// --- SEP Coprocessor ---

@interface _VZSEPCoprocessorConfiguration : NSObject
- (instancetype)initWithStorageURL:(NSURL *)url;
- (void)setRomBinaryURL:(NSURL *)url;
- (void)setDebugStub:(id)stub;
@end

id VPhoneCreateSEPCoprocessorConfig(NSURL *storageURL) {
  Class cls = NSClassFromString(@"_VZSEPCoprocessorConfiguration");
  if (!cls) {
    NSLog(@"[vphone] WARNING: _VZSEPCoprocessorConfiguration not found");
    return nil;
  }
  _VZSEPCoprocessorConfiguration *config = [[cls alloc] initWithStorageURL:storageURL];
  return config;
}

void VPhoneSetSEPRomBinaryURL(id sepConfig, NSURL *romURL) {
  if ([sepConfig respondsToSelector:@selector(setRomBinaryURL:)]) {
    [sepConfig performSelector:@selector(setRomBinaryURL:) withObject:romURL];
  }
}

void VPhoneConfigureSEP(VZVirtualMachineConfiguration *config,
                        NSURL *sepStorageURL,
                        NSURL *sepRomURL) {
  id sepConfig = VPhoneCreateSEPCoprocessorConfig(sepStorageURL);
  if (!sepConfig) {
    NSLog(@"[vphone] Failed to create SEP coprocessor config");
    return;
  }
  if (sepRomURL) {
    VPhoneSetSEPRomBinaryURL(sepConfig, sepRomURL);
  }
  // Set debug stub on SEP (same as vrevm)
  Class stubClass = NSClassFromString(@"_VZGDBDebugStubConfiguration");
  if (stubClass) {
    id sepDebugStub = [[stubClass alloc] init];
    [sepConfig performSelector:@selector(setDebugStub:) withObject:sepDebugStub];
  }
  [config _setCoprocessors:@[sepConfig]];
  NSLog(@"[vphone] SEP coprocessor configured (storage: %@)", sepStorageURL.path);
}

void VPhoneSetGDBDebugStubDefault(VZVirtualMachineConfiguration *config) {
  Class stubClass = NSClassFromString(@"_VZGDBDebugStubConfiguration");
  if (!stubClass) {
    NSLog(@"[vphone] WARNING: _VZGDBDebugStubConfiguration not found");
    return;
  }
  id stub = [[stubClass alloc] init]; // default init, no specific port (same as vrevm)
  [config _setDebugStub:stub];
}

// --- Multi-Touch (VNC click fix) ---

@interface _VZMultiTouchDeviceConfiguration : NSObject <NSCopying>
@end

@interface _VZUSBTouchScreenConfiguration : _VZMultiTouchDeviceConfiguration
- (instancetype)init;
@end

void VPhoneConfigureMultiTouch(VZVirtualMachineConfiguration *config) {
  Class cls = NSClassFromString(@"_VZUSBTouchScreenConfiguration");
  if (!cls) {
    NSLog(@"[vphone] WARNING: _VZUSBTouchScreenConfiguration not found");
    return;
  }
  id touchConfig = [[cls alloc] init];
  [config _setMultiTouchDevices:@[touchConfig]];
  NSLog(@"[vphone] USB touch screen configured");
}

// VZTouchHelper: create _VZTouch using KVC to avoid crash in initWithView:...
// The _VZTouch initializer does a struct copy (objc_copyStruct) that causes
// EXC_BAD_ACCESS (SIGBUS) when called from Swift Dynamic framework.
// Using alloc+init then KVC setValue:forKey: bypasses the problematic initializer.
id VPhoneCreateTouch(NSInteger index,
                      NSInteger phase,
                      CGPoint location,
                      NSInteger swipeAim,
                      NSTimeInterval timestamp) {
  Class touchClass = NSClassFromString(@"_VZTouch");
  if (!touchClass) {
    return nil;
  }

  id touch = [[touchClass alloc] init];

  [touch setValue:@((unsigned char)index) forKey:@"_index"];
  [touch setValue:@(phase) forKey:@"_phase"];
  [touch setValue:@(swipeAim) forKey:@"_swipeAim"];
  [touch setValue:@(timestamp) forKey:@"_timestamp"];
  [touch setValue:[NSValue valueWithPoint:location] forKey:@"_location"];

  return touch;
}

id VPhoneCreateMultiTouchEvent(NSArray *touches) {
  Class cls = NSClassFromString(@"_VZMultiTouchEvent");
  if (!cls) {
    return nil;
  }
  // _VZMultiTouchEvent initWithTouches:
  SEL sel = NSSelectorFromString(@"initWithTouches:");
  id event = [cls alloc];
  id (*initWithTouches)(id, SEL, NSArray *) = (id (*)(id, SEL, NSArray *))objc_msgSend;
  return initWithTouches(event, sel, touches);
}

NSArray *VPhoneGetMultiTouchDevices(VZVirtualMachine *vm) {
  SEL sel = NSSelectorFromString(@"_multiTouchDevices");
  if (![vm respondsToSelector:sel]) {
    return nil;
  }
  NSArray * (*getter)(id, SEL) = (NSArray * (*)(id, SEL))objc_msgSend;
  return getter(vm, sel);
}

void VPhoneSendMultiTouchEvents(id multiTouchDevice, NSArray *events) {
  SEL sel = NSSelectorFromString(@"sendMultiTouchEvents:");
  if (![multiTouchDevice respondsToSelector:sel]) {
    return;
  }
  void (*send)(id, SEL, NSArray *) = (void (*)(id, SEL, NSArray *))objc_msgSend;
  send(multiTouchDevice, sel, events);
}
