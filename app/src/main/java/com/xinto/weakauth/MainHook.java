package com.x1nto.weakauth; // Keep the existing package name from the repo

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String SYSTEM_UI_PACKAGE = "com.android.systemui";
    private static final int STRONG_AUTH_NOT_REQUIRED = 0x0;
    private static final int STRONG_AUTH_REQUIRED_AFTER_BOOT = 0x1;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!SYSTEM_UI_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        // 1. Hook base LockPatternUtils$StrongAuthTracker (used by Android 14 BiometricSettingsRepository)
        try {
            Class<?> baseTrackerClass = XposedHelpers.findClass(
                    "com.android.internal.widget.LockPatternUtils$StrongAuthTracker",
                    lpparam.classLoader
            );

            // Clear all StrongAuth timeout/lockout flags except right after boot (0x1)
            XposedHelpers.findAndHookMethod(
                    baseTrackerClass,
                    "getStrongAuthForUser",
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            int flags = (int) param.getResult();
                            if ((flags & STRONG_AUTH_REQUIRED_AFTER_BOOT) == 0) {
                                param.setResult(STRONG_AUTH_NOT_REQUIRED);
                            }
                        }
                    }
            );

            // Allow non-strong/convenience biometrics (e.g., 2D face unlock) after idle timeout
            XposedHelpers.findAndHookMethod(
                    baseTrackerClass,
                    "isNonStrongBiometricAllowedAfterIdleTimeout",
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            int userId = (int) param.args[0];
                            int flags = (int) XposedHelpers.callMethod(
                                    param.thisObject,
                                    "getStrongAuthForUser",
                                    userId
                            );
                            if ((flags & STRONG_AUTH_REQUIRED_AFTER_BOOT) == 0) {
                                param.setResult(true);
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("WeakAuth: Failed to hook LockPatternUtils$StrongAuthTracker: " + t);
        }

        // 2. Hook KeyguardUpdateMonitor$StrongAuthTracker for legacy and direct checks
        try {
            Class<?> kgTrackerClass = XposedHelpers.findClass(
                    "com.android.keyguard.KeyguardUpdateMonitor$StrongAuthTracker",
                    lpparam.classLoader
            );

            XposedHelpers.findAndHookMethod(
                    kgTrackerClass,
                    "isUnlockingWithBiometricAllowed",
                    boolean.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            int userId = (int) XposedHelpers.callStaticMethod(
                                    XposedHelpers.findClass("com.android.keyguard.KeyguardUpdateMonitor", lpparam.classLoader),
                                    "getCurrentUser"
                            );
                            int flags = (int) XposedHelpers.callMethod(
                                    param.thisObject,
                                    "getStrongAuthForUser",
                                    userId
                            );
                            if ((flags & STRONG_AUTH_REQUIRED_AFTER_BOOT) == 0) {
                                param.setResult(true);
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            XposedBridge.log("WeakAuth: KeyguardUpdateMonitor$StrongAuthTracker hook skipped: " + t);
        }
    }
}
