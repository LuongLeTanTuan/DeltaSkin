// DeltaSkin Patcher - a standalone TrollStore app.
//
// Install it, tap Patch, and the next launch of Delta Force has the skin menu.
// Nothing is injected into the game at runtime by this app: it edits the game's
// main executable once (LC_LOAD_DYLIB + ad-hoc re-sign), drops DeltaSkin.dylib
// into Frameworks/, and keeps a copy of the untouched executable so Restore puts
// everything back.
//
// The entitlements in patcher/entitlements.plist (platform-application,
// no-sandbox) are what let a separate app write into another app's bundle. They
// only take effect because TrollStore installs the TIPA without validating them
// against a provisioning profile.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

#include "macho.h"

static NSMutableString *gLog = nil;
static UILabel *gStatusLabel = nil;
static UITextView *gLogView = nil;

static void UIAppend(NSString *line) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLog) gLog = [NSMutableString string];
        [gLog appendString:line];
        [gLog appendString:@"\n"];
        gLogView.text = gLog;
        if (gLog.length) {
            NSRange end = NSMakeRange(gLog.length - 1, 1);
            [gLogView scrollRangeToVisible:end];
        }
    });
}

static void UISetStatus(NSString *s) {
    dispatch_async(dispatch_get_main_queue(), ^{ gStatusLabel.text = s; });
}

// --------------------------------------------------------------- game lookup
static NSString *const kDylibName = @"DeltaSkin.dylib";
static NSString *const kInstallPath = @"@executable_path/Frameworks/DeltaSkin.dylib";
// The identity the patcher is built for. Matched first, because the executable
// name and the bundle id of a sideloaded build can both be changed by whoever
// repackaged it, while this is what the store build actually ships.
static NSString *const kGameBundleID = @"com.garena.game.df";

static BOOL DSIsGameApp(NSString *appPath) {
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [appPath stringByAppendingPathComponent:@"Info.plist"]];
    if (!info) return NO;
    NSString *exe = info[@"CFBundleExecutable"] ?: @"";
    NSString *bid = [(info[@"CFBundleIdentifier"] ?: @"") lowercaseString];
    if ([bid isEqualToString:kGameBundleID]) return YES;
    if ([exe isEqualToString:@"DeltaForceClient"]) return YES;
    if ([bid containsString:@"deltaforce"]) return YES;
    if ([bid containsString:@"deltawar"]) return YES;
    return NO;
}

// TrollStore installs land in /var/Containers/Bundle/Application/<UUID>/<name>.app
// on iOS 14 and in /var/mobile/Containers/Bundle/Application/... on 15+. System
// apps sit directly in /Applications. All three shapes are walked.
static NSString *DSFindGameApp(void) {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray<NSString *> *roots = @[
        @"/var/Containers/Bundle/Application",
        @"/var/mobile/Containers/Bundle/Application",
        @"/Applications",
    ];
    for (NSString *root in roots) {
        NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:root error:nil];
        for (NSString *entry in entries) {
            NSString *p = [root stringByAppendingPathComponent:entry];
            if ([entry hasSuffix:@".app"]) {
                if (DSIsGameApp(p)) return p;
                continue;
            }
            for (NSString *inner in [fm contentsOfDirectoryAtPath:p error:nil]) {
                if (![inner hasSuffix:@".app"]) continue;
                NSString *app = [p stringByAppendingPathComponent:inner];
                if (DSIsGameApp(app)) return app;
            }
        }
    }
    return nil;
}

static NSString *DSBackupDir(NSString *bundleID) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *safe = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    return [[docs stringByAppendingPathComponent:@"backup"] stringByAppendingPathComponent:safe];
}

static int DSRunPatch(BOOL restore);

// ---------------------------------------------------------------------- UI
@interface DSRoot : UIViewController
@end

@implementation DSRoot

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.055 green:0.058 blue:0.070 alpha:1];

    CGRect b = self.view.bounds;
    CGFloat pad = 20.0;

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(pad, 60, b.size.width - pad * 2, 30)];
    title.text = @"DeltaSkin";
    title.font = [UIFont systemFontOfSize:26 weight:UIFontWeightBold];
    title.textColor = [UIColor colorWithWhite:0.95 alpha:1];
    title.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:title];

    gStatusLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, 94, b.size.width - pad * 2, 40)];
    gStatusLabel.numberOfLines = 2;
    gStatusLabel.font = [UIFont systemFontOfSize:12];
    gStatusLabel.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    gStatusLabel.text = @"looking for the game...";
    gStatusLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:gStatusLabel];

    UIButton *patch = [UIButton buttonWithType:UIButtonTypeSystem];
    patch.frame = CGRectMake(pad, 146, b.size.width - pad * 2, 50);
    patch.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [patch setTitle:@"Patch" forState:UIControlStateNormal];
    [patch setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    patch.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightSemibold];
    patch.backgroundColor = [UIColor colorWithRed:0.20 green:0.80 blue:0.50 alpha:0.95];
    patch.layer.cornerRadius = 12;
    [patch addTarget:self action:@selector(patchTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:patch];

    UIButton *restore = [UIButton buttonWithType:UIButtonTypeSystem];
    restore.frame = CGRectMake(pad, 204, b.size.width - pad * 2, 44);
    restore.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [restore setTitle:@"Restore original" forState:UIControlStateNormal];
    [restore setTitleColor:[UIColor colorWithWhite:0.85 alpha:1] forState:UIControlStateNormal];
    restore.titleLabel.font = [UIFont systemFontOfSize:14];
    restore.backgroundColor = [UIColor colorWithWhite:1 alpha:0.07];
    restore.layer.cornerRadius = 12;
    [restore addTarget:self action:@selector(restoreTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:restore];

    CGFloat logTop = 260.0;
    gLogView = [[UITextView alloc] initWithFrame:CGRectMake(pad, logTop, b.size.width - pad * 2,
                                                            b.size.height - logTop - pad)];
    gLogView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    gLogView.backgroundColor = [UIColor colorWithWhite:1 alpha:0.04];
    gLogView.layer.cornerRadius = 10;
    gLogView.editable = NO;
    gLogView.textColor = [UIColor colorWithWhite:0.72 alpha:1];
    gLogView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    gLogView.text = @"";
    [self.view addSubview:gLogView];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self refreshStatus]; });
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [self refreshStatus];
}

- (void)refreshStatus {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSString *app = DSFindGameApp();
        if (!app) { UISetStatus(@"game not found - is Delta Force installed?"); return; }
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                              [app stringByAppendingPathComponent:@"Info.plist"]];
        NSString *bid = info[@"CFBundleIdentifier"] ?: @"?";
        NSString *bd = DSBackupDir(bid);
        BOOL backed = [NSFileManager.defaultManager fileExistsAtPath:
                       [bd stringByAppendingPathComponent:@"patched"]];
        UISetStatus([NSString stringWithFormat:@"%@\n%@", app,
                     backed ? @"state: patched (Restore available)" : @"state: untouched"]);
        UIAppend([NSString stringWithFormat:@"found %@", app]);
    });
}

- (void)patchTapped {
    UIAppend(@"--- patch ---");
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ DSRunPatch(NO); });
}

- (void)restoreTapped {
    UIAppend(@"--- restore ---");
    dispatch_async(dispatch_get_global_queue(0, 0), ^{ DSRunPatch(YES); });
}

@end

// ------------------------------------------------------------------ the work
static NSString *DSDylibPath(void) {
    return [[NSBundle mainBundle] pathForResource:@"DeltaSkin" ofType:@"dylib"];
}

static int DSRunPatch(BOOL restore) {
    char err[256] = {0};
    NSFileManager *fm = NSFileManager.defaultManager;

    NSString *app = DSFindGameApp();
    if (!app) { UISetStatus(@"game not found"); UIAppend(@"game not found"); return -1; }

    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                          [app stringByAppendingPathComponent:@"Info.plist"]];
    NSString *exe = info[@"CFBundleExecutable"];
    NSString *bid = info[@"CFBundleIdentifier"] ?: @"unknown";
    if (!exe.length) { UISetStatus(@"Info.plist has no CFBundleExecutable"); return -1; }

    NSString *exePath = [app stringByAppendingPathComponent:exe];
    NSString *bd = DSBackupDir(bid);
    NSString *bakExe = [bd stringByAppendingPathComponent:exe];
    NSString *bakInfo = [bd stringByAppendingPathComponent:@"Info.plist"];
    NSString *marker = [bd stringByAppendingPathComponent:@"patched"];

    UIAppend([NSString stringWithFormat:@"target  %@", exePath]);

    if (restore) {
        if (![fm fileExistsAtPath:bakExe]) {
            UISetStatus(@"no backup to restore");
            UIAppend(@"no backup found");
            return -1;
        }
        if ([fm fileExistsAtPath:exePath]) [fm removeItemAtPath:exePath error:nil];
        if (![fm copyItemAtPath:bakExe toPath:exePath error:nil]) {
            UISetStatus(@"restore failed: cannot write the executable");
            return -1;
        }
        if ([fm fileExistsAtPath:bakInfo])
            [fm copyItemAtPath:bakInfo toPath:[app stringByAppendingPathComponent:@"Info.plist"] error:nil];
        [fm removeItemAtPath:marker error:nil];
        UISetStatus(@"restored - the game is untouched again");
        UIAppend(@"restored");
        return 0;
    }

    NSString *dylib = DSDylibPath();
    if (!dylib.length) { UISetStatus(@"DeltaSkin.dylib missing from the app bundle"); return -1; }
    UIAppend([NSString stringWithFormat:@"payload %@", dylib]);

    // 1. One-time backup of the two files this app can change.
    if (![fm fileExistsAtPath:bakExe]) {
        [fm createDirectoryAtPath:bd withIntermediateDirectories:YES attributes:nil error:nil];
        if (![fm copyItemAtPath:exePath toPath:bakExe error:nil]) {
            UISetStatus(@"cannot back up the executable - check the app's entitlements");
            UIAppend(@"backup failed");
            return -1;
        }
        [fm copyItemAtPath:[app stringByAppendingPathComponent:@"Info.plist"] toPath:bakInfo error:nil];
        UIAppend(@"backup written");
    }

    // 2. Payload.
    NSString *fw = [app stringByAppendingPathComponent:@"Frameworks"];
    [fm createDirectoryAtPath:fw withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *dst = [fw stringByAppendingPathComponent:kDylibName];
    [fm removeItemAtPath:dst error:nil];
    if (![fm copyItemAtPath:dylib toPath:dst error:nil]) {
        UISetStatus(@"cannot write Frameworks/DeltaSkin.dylib");
        UIAppend(@"payload copy failed");
        return -1;
    }
    UIAppend(@"payload copied");

    // 3. Inject + re-sign. The game's own entitlements and its existing CMS blob
    //    are carried over from the signature already on disk, inside this call;
    //    dropping them loses keychain/app-group access and the game stops
    //    signing in.
    UISetStatus(@"patching...");
    int rc = mo_inject_and_sign(exePath.UTF8String, kInstallPath.UTF8String,
                                NULL, 0, err, sizeof(err));

    if (rc != 0) {
        NSString *m = [NSString stringWithFormat:@"patch failed: %s", err[0] ? err : "unknown"];
        UIAppend(m);
        UISetStatus(m);
        return rc;
    }

    [fm createFileAtPath:marker contents:[NSData data] attributes:nil];
    UIAppend(@"done");
    UISetStatus(@"patched - open Delta Force, the DS button is top right");
    return 0;
}

// ---------------------------------------------------------------------- main
@interface DSAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation DSAppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [DSRoot new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([DSAppDelegate class]));
    }
}
