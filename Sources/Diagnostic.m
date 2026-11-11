#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdint.h>

static NSMutableArray<NSString *> *P8Logs;
static UITextView *P8TextView;
static UIWindow *P8Window;
static UIView *P8Panel;
static UIButton *P8Bubble;
static NSUInteger P8Sequence;

static void P8Log(NSString *message) {
    if (!P8Logs) P8Logs = [NSMutableArray new];
    NSString *line = [NSString stringWithFormat:@"[%@] %@", [NSDateFormatter localizedStringFromDate:[NSDate date] dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterMediumStyle], message];
    [P8Logs addObject:line];
    if (P8Logs.count > 1000) [P8Logs removeObjectsInRange:NSMakeRange(0, P8Logs.count - 1000)];
    if (P8TextView) P8TextView.text = [P8Logs componentsJoinedByString:@"\n"];
}

@interface P8DiagnosticController : UIViewController
@end
@implementation P8DiagnosticController
- (void)loadView { self.view = [[UIView alloc] initWithFrame:[UIScreen mainScreen].bounds]; self.view.backgroundColor = UIColor.clearColor; }
- (void)viewDidLoad {
    [super viewDidLoad];
    P8Bubble = [UIButton buttonWithType:UIButtonTypeSystem];
    P8Bubble.frame = CGRectMake(12, 150, 52, 52);
    P8Bubble.layer.cornerRadius = 26;
    P8Bubble.backgroundColor = [UIColor colorWithRed:0.12 green:0.18 blue:0.28 alpha:0.94];
    [P8Bubble setTitle:@"DBG" forState:UIControlStateNormal];
    [P8Bubble setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [P8Bubble addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [P8Bubble addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)]];
    [self.view addSubview:P8Bubble];

    CGFloat width = MIN(340, self.view.bounds.size.width - 24);
    CGFloat height = MIN(440, self.view.bounds.size.height - 80);
    P8Panel = [[UIView alloc] initWithFrame:CGRectMake(12, 210, width, height)];
    P8Panel.backgroundColor = [UIColor colorWithRed:0.05 green:0.07 blue:0.11 alpha:0.97];
    P8Panel.layer.cornerRadius = 12;
    P8Panel.hidden = YES;
    [self.view addSubview:P8Panel];
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, width - 24, 30)];
    title.text = @"Pool8 Diagnostic V2";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:16];
    [P8Panel addSubview:title];
    P8TextView = [[UITextView alloc] initWithFrame:CGRectMake(8, 44, width - 16, height - 104)];
    P8TextView.backgroundColor = [UIColor colorWithRed:0.02 green:0.03 blue:0.05 alpha:1];
    P8TextView.textColor = [UIColor colorWithRed:0.65 green:0.88 blue:0.75 alpha:1];
    P8TextView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    P8TextView.editable = NO;
    [P8Panel addSubview:P8TextView];
    NSArray *labels = @[@"Copy", @"Clear", @"Snapshot", @"Close"];
    NSArray *actions = @[@"copyLogs", @"clearLogs", @"snapshot", @"toggle"];
    CGFloat buttonWidth = (width - 20) / 4;
    for (NSInteger i=0; i<labels.count; i++) {
        UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
        b.frame = CGRectMake(10 + i * buttonWidth, height - 53, buttonWidth - 3, 42);
        [b setTitle:labels[i] forState:UIControlStateNormal];
        [b setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        b.titleLabel.font = [UIFont systemFontOfSize:12];
        b.backgroundColor = [UIColor colorWithRed:0.16 green:0.23 blue:0.34 alpha:1];
        b.layer.cornerRadius = 7;
        [b addTarget:self action:NSSelectorFromString(actions[i]) forControlEvents:UIControlEventTouchUpInside];
        [P8Panel addSubview:b];
    }
    P8Log(@"Diagnostic UI ready. Runtime address inspection enabled; prediction hooks not installed.");
}
- (void)drag:(UIPanGestureRecognizer *)gesture {
    CGPoint delta = [gesture translationInView:self.view];
    CGPoint center = P8Bubble.center;
    center.x = MAX(26, MIN(self.view.bounds.size.width - 26, center.x + delta.x));
    center.y = MAX(26, MIN(self.view.bounds.size.height - 26, center.y + delta.y));
    P8Bubble.center = center;
    [gesture setTranslation:CGPointZero inView:self.view];
}
- (void)toggle { P8Panel.hidden = !P8Panel.hidden; }
- (void)copyLogs { [UIPasteboard generalPasteboard].string = [P8Logs componentsJoinedByString:@"\n"]; P8Log(@"Logs copied to clipboard"); }
- (void)clearLogs { [P8Logs removeAllObjects]; P8TextView.text = @""; P8Log(@"Logs cleared"); }
- (void)snapshot {
    P8Sequence++;
    P8Log([NSString stringWithFormat:@"SNAPSHOT #%lu | loaded images=%u", (unsigned long)P8Sequence, _dyld_image_count()]);
    for (uint32_t i=0; i<_dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "libloader") || strstr(name, "pool.app"))) P8Log([NSString stringWithFormat:@"IMAGE %s", name]);
    }
    BOOL found = NO;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "libloader.framework/libloader")) continue;
        const struct mach_header *header = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (!header || header->magic != MH_MAGIC_64) {
            P8Log(@"LIBLOADER: unexpected Mach-O header; skipping address calculation");
            continue;
        }
        const struct mach_header_64 *h = (const struct mach_header_64 *)header;
        uintptr_t textVM = 0;
        BOOL textFound = NO;
        const uint8_t *cursor = (const uint8_t *)(h + 1);
        for (uint32_t j = 0; j < h->ncmds; j++) {
            const struct load_command *cmd = (const struct load_command *)cursor;
            if (cmd->cmdsize < sizeof(struct load_command)) break;
            if (cmd->cmd == LC_SEGMENT_64 && cmd->cmdsize >= sizeof(struct segment_command_64)) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
                if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                    textVM = (uintptr_t)seg->vmaddr;
                    textFound = YES;
                    break;
                }
            }
            cursor += cmd->cmdsize;
        }
        if (!textFound) {
            P8Log(@"LIBLOADER: __TEXT segment not found");
            continue;
        }
        found = YES;
        uintptr_t base = (uintptr_t)((intptr_t)textVM + slide);
        P8Log([NSString stringWithFormat:@"LIBLOADER image=%p | slide=%p | __TEXT base=%p", header, (void *)slide, (void *)base]);
        P8Log([NSString stringWithFormat:@"CANDIDATE trajectory reader VM=0x28E09C runtime=%p", (void *)(base + 0x28E09C)]);
        P8Log([NSString stringWithFormat:@"CANDIDATE trajectory comparator VM=0x28C390 runtime=%p", (void *)(base + 0x28C390)]);
    }
    if (!found) P8Log(@"LIBLOADER: not found or unable to inspect __TEXT");
    P8Log(@"Prediction values/call counts unavailable: no function hooks installed");
}
@end

// Only the bubble/panel receive touch events; gameplay remains interactive elsewhere.
@interface P8PassThroughWindow : UIWindow @end
@implementation P8PassThroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    if (!hit || hit == self.rootViewController.view) return nil;
    return hit;
}
@end

static void P8Start(void) {
    if (P8Window) return;
    P8Window = [[P8PassThroughWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    P8Window.windowLevel = UIWindowLevelAlert + 1;
    P8Window.rootViewController = [P8DiagnosticController new];
    P8Window.hidden = NO;
    P8Log(@"Diagnostic library loaded");
}

__attribute__((constructor)) static void P8Initialize(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        // Wait for the host application to have an active scene/window.
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(__unused NSNotification *note) { P8Start(); }];
        if ([UIApplication sharedApplication].applicationState == UIApplicationStateActive) P8Start();
    });
}
