/**
 * Device fingerprinting utility for abuse prevention.
 *
 * Generates a SHA-256 hash of browser/device characteristics to help
 * identify when multiple accounts are created from the same device.
 *
 * Note: This is not a security feature but an abuse prevention mechanism.
 * Fingerprints can be spoofed by determined users.
 */

interface FingerprintComponents {
  canvas: string;
  webgl: string;
  fonts: string[];
  screen: string;
  timezone: string;
  language: string;
  platform: string;
  plugins: string[];
  hardwareConcurrency: number;
  deviceMemory: number | undefined;
  touchSupport: boolean;
  colorDepth: number;
}

/**
 * Generate a canvas fingerprint by drawing text and shapes.
 */
function getCanvasFingerprint(): string {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'no-canvas';

    canvas.width = 200;
    canvas.height = 50;

    // Draw text with various styles
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('A13E Fingerprint', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Canvas Test', 4, 17);

    // Draw some shapes
    ctx.beginPath();
    ctx.arc(50, 25, 10, 0, Math.PI * 2);
    ctx.fill();

    return canvas.toDataURL();
  } catch {
    return 'canvas-error';
  }
}

/**
 * Generate a WebGL fingerprint from renderer info.
 */
function getWebGLFingerprint(): string {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'no-webgl';

    const webgl = gl as WebGLRenderingContext;
    const debugInfo = webgl.getExtension('WEBGL_debug_renderer_info');

    if (debugInfo) {
      const vendor = webgl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      const renderer = webgl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
      return `${vendor}~${renderer}`;
    }

    return webgl.getParameter(webgl.VENDOR) + '~' + webgl.getParameter(webgl.RENDERER);
  } catch {
    return 'webgl-error';
  }
}

/**
 * Detect available fonts by measuring text width differences.
 */
function getAvailableFonts(): string[] {
  const baseFonts = ['monospace', 'sans-serif', 'serif'];
  const testFonts = [
    'Arial',
    'Arial Black',
    'Comic Sans MS',
    'Courier New',
    'Georgia',
    'Impact',
    'Lucida Console',
    'Palatino Linotype',
    'Tahoma',
    'Times New Roman',
    'Trebuchet MS',
    'Verdana',
    'Helvetica',
    'Monaco',
    'Consolas',
  ];

  const testString = 'mmmmmmmmmmlli';
  const testSize = '72px';
  const available: string[] = [];

  const span = document.createElement('span');
  span.style.position = 'absolute';
  span.style.left = '-9999px';
  span.style.fontSize = testSize;
  span.innerText = testString;
  document.body.appendChild(span);

  const baseWidths: Record<string, number> = {};
  for (const baseFont of baseFonts) {
    span.style.fontFamily = baseFont;
    baseWidths[baseFont] = span.offsetWidth;
  }

  for (const font of testFonts) {
    let detected = false;
    for (const baseFont of baseFonts) {
      span.style.fontFamily = `'${font}', ${baseFont}`;
      if (span.offsetWidth !== baseWidths[baseFont]) {
        detected = true;
        break;
      }
    }
    if (detected) {
      available.push(font);
    }
  }

  document.body.removeChild(span);
  return available;
}

/**
 * Get screen characteristics.
 */
function getScreenFingerprint(): string {
  const { width, height, colorDepth, pixelDepth } = window.screen;
  const ratio = window.devicePixelRatio || 1;
  return `${width}x${height}x${colorDepth}x${pixelDepth}@${ratio}`;
}

/**
 * Get browser plugins list.
 */
function getPlugins(): string[] {
  const plugins: string[] = [];
  if (navigator.plugins) {
    for (let i = 0; i < navigator.plugins.length; i++) {
      const plugin = navigator.plugins[i];
      if (plugin?.name) {
        plugins.push(plugin.name);
      }
    }
  }
  return plugins.sort();
}

/**
 * Check for touch support.
 */
function hasTouchSupport(): boolean {
  return (
    'ontouchstart' in window ||
    navigator.maxTouchPoints > 0 ||

    (navigator as any).msMaxTouchPoints > 0
  );
}

/**
 * Collect all fingerprint components.
 */
function collectComponents(): FingerprintComponents {
  return {
    canvas: getCanvasFingerprint(),
    webgl: getWebGLFingerprint(),
    fonts: getAvailableFonts(),
    screen: getScreenFingerprint(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language,
    platform: navigator.platform,
    plugins: getPlugins(),
    hardwareConcurrency: navigator.hardwareConcurrency || 0,

    deviceMemory: (navigator as any).deviceMemory,
    touchSupport: hasTouchSupport(),
    colorDepth: window.screen.colorDepth,
  };
}

/**
 * Hash the fingerprint components using SHA-256.
 */
async function hashComponents(components: FingerprintComponents): Promise<string> {
  const data = JSON.stringify(components);
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a device fingerprint hash.
 *
 * @returns Promise<string> - 64-character SHA-256 hash
 */
export async function generateFingerprint(): Promise<string> {
  try {
    const components = collectComponents();
    return await hashComponents(components);
  } catch (error) {
    console.error('Error generating fingerprint:', error);
    // Return a fallback hash based on basic info
    const fallback = `fallback-${navigator.userAgent}-${Date.now()}`;
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(fallback));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
}

/**
 * Get a cached fingerprint or generate a new one.
 * Caches in sessionStorage to avoid regenerating on every request.
 */
export async function getFingerprint(): Promise<string> {
  const cacheKey = 'a13e_device_fingerprint';
  const cached = sessionStorage.getItem(cacheKey);

  if (cached) {
    return cached;
  }

  const fingerprint = await generateFingerprint();
  sessionStorage.setItem(cacheKey, fingerprint);
  return fingerprint;
}

/**
 * Clear the cached fingerprint.
 */
export function clearFingerprintCache(): void {
  sessionStorage.removeItem('a13e_device_fingerprint');
}
