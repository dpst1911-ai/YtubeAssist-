#!/usr/bin/env python3
"""Static source security gates for YTWatchAssist, not a malware certification."""
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT = Path(__file__).resolve().parents[1]
ANDROID = '{http://schemas.android.com/apk/res/android}'
manifest = ET.parse(ROOT/'app/src/main/AndroidManifest.xml').getroot()
app = manifest.find('application')
a11y = ET.parse(ROOT/'app/src/main/res/xml/accessibility_service.xml').getroot()
java = (ROOT/'app/src/main/java/com/ytwatch/assist/YouTubeAssistService.java').read_text()
prefs = (ROOT/'app/src/main/java/com/ytwatch/assist/AppPreferences.java').read_text()
activity = (ROOT/'app/src/main/java/com/ytwatch/assist/MainActivity.java').read_text()
gradle = (ROOT/'app/build.gradle').read_text()
checks = {
 'no application uses-permission': not manifest.findall('uses-permission'),
 'no internet': 'android.permission.INTERNET' not in ET.tostring(manifest).decode(),
 'no SMS': 'READ_SMS' not in ET.tostring(manifest).decode() and 'RECEIVE_SMS' not in ET.tostring(manifest).decode(),
 'no notifications listener': 'NotificationListenerService' not in ET.tostring(manifest).decode(),
 'backup off': app.get(ANDROID+'allowBackup')=='false',
 'no cleartext': app.get(ANDROID+'usesCleartextTraffic')=='false',
 'one explicit a11y service': len(app.findall('service')) == 1,
 'only YouTube accessibility events': a11y.get(ANDROID+'packageNames')=='com.google.android.youtube',
 'screen sampling declared explicitly': a11y.get(ANDROID+'canTakeScreenshot')=='true',
 'not mislabeled as disability tool': 'isAccessibilityTool' not in ET.tostring(a11y).decode(),
 'accessibility permission required': app.find('service').get(ANDROID+'permission')=='android.permission.BIND_ACCESSIBILITY_SERVICE',
 'cleartext user disclosure': 'دسترسی حساس:' in activity and 'موافقم:' in activity,
 'primary consent defaults denied': 'prefs(c).getBoolean(CONSENT, false)' in prefs,
 'screen capture consent defaults denied': 'prefs(c).getBoolean(SCREENSHOT_CONSENT, false)' in prefs,
 'screen feature defaults denied': 'prefs(c).getBoolean(BLACK, false)' in prefs,
 'consent revocation clears capture': 'if (!allowed) editor.putBoolean(SCREENSHOT_CONSENT, false)' in prefs,
 'enable button disabled until consent': 'enable.setEnabled(AppPreferences.hasConsent(this))' in activity,
 'consent guard before event handling': 'event == null || !AppPreferences.hasConsent(this)' in java,
 'consent guard before root scan': 'if (!AppPreferences.hasConsent(this)) { stopActivity(); return; }' in java,
 'consent guard before screenshot request': 'if (!AppPreferences.hasConsent(this) || !isYouTube(getRootInActiveWindow())) return;' in java,
 'consent and foreground guard in screenshot callback': ('!AppPreferences.blackRecovery(YouTubeAssistService.this)' in java and '|| !isYouTube(getRootInActiveWindow())) {' in java),
 'hardware buffer always closed in finally': 'buffer.close();' in java and 'finally {' in java,
 'screen sample only not save': 'getPixel(x, y)' in java and 'FileOutputStream' not in java,
 'no socket, telemetry, or HTTP code': not any(p in java for p in ('HttpURLConnection', 'Socket(', 'WebView(', 'https://')),
 'version bump applied': "versionName '1.2.0'" in gradle,
}
for name, ok in checks.items():
    print(('PASS' if ok else 'FAIL') + ' ' + name)
if not all(checks.values()):
    raise SystemExit(1)
print(f'PASS security gate {len(checks)} source checks; Play Protect acceptance NOT implied')
