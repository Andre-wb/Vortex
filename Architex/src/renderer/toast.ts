/** Programmatic toast/notification system for Architex. */

let _toastContainer: HTMLElement | null = null;

function getToastContainer(): HTMLElement {
  if (_toastContainer && _toastContainer.isConnected) return _toastContainer;

  _toastContainer = document.createElement('div');
  _toastContainer.className = 'arx-toast-container';
  document.body.appendChild(_toastContainer);
  return _toastContainer;
}

export type ToastType = 'success' | 'error' | 'warning' | 'info';

/**
 * Show a toast notification.
 * @param message  Text to display.
 * @param type     Toast type — controls background color.
 * @param duration Auto-dismiss duration in ms (0 = no auto-dismiss).
 */
export function showToast(
  message:  string,
  type:     ToastType = 'info',
  duration  = 3000,
): void {
  const container = getToastContainer();

  const toast = document.createElement('div');
  toast.className = `arx-toast arx-toast-${type}`;
  toast.textContent = message;

  // Set animation delay for fadeOut
  const fadeOutDelay = Math.max(0, duration - 300);
  toast.style.animationDelay = `0s, ${fadeOutDelay}ms`;
  toast.style.animationDuration = '0.3s, 0.3s';

  container.appendChild(toast);

  if (duration > 0) {
    setTimeout(() => {
      if (toast.parentNode) toast.remove();
    }, duration);
  }
}
