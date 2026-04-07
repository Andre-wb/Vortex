import type { CapacitorConfig } from '@anthropic/capacitor/cli';

const config: CapacitorConfig = {
  appId: 'org.vortex.messenger',
  appName: 'Vortex',
  webDir: 'static',
  server: {
    androidScheme: 'https',
    iosScheme: 'https',
  },
  plugins: {
    PushNotifications: {
      presentationOptions: ['badge', 'sound', 'alert'],
    },
    LocalNotifications: {
      smallIcon: 'ic_notification',
      iconColor: '#7C3AED',
    },
    SplashScreen: {
      launchShowDuration: 1500,
      backgroundColor: '#0E0E18',
      showSpinner: false,
      androidScaleType: 'CENTER_CROP',
      splashFullScreen: true,
      splashImmersive: true,
    },
    Keyboard: {
      resize: 'body',
      style: 'dark',
      resizeOnFullScreen: true,
    },
    StatusBar: {
      style: 'dark',
      backgroundColor: '#0E0E18',
    },
    CapacitorHttp: {
      enabled: true,
    },
    Badge: {
      persist: true,
      autoClear: false,
    },
  },
  ios: {
    contentInset: 'automatic',
    preferredContentMode: 'mobile',
    backgroundColor: '#0E0E18',
    allowsLinkPreview: true,
    scrollEnabled: true,
    limitsNavigationsToAppBoundDomains: true,
  },
  android: {
    allowMixedContent: false,
    backgroundColor: '#0E0E18',
    captureInput: true,
    webContentsDebuggingEnabled: false,
    loggingBehavior: 'none',
    useLegacyBridge: false,
  },
};

export default config;
